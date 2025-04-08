<#
.SYNOPSIS
	Create a Self Signed certificate, create a CSR and Private key or export a certificate to PFX
.DESCRIPTION
	This script has several options to create a Self Signed Certificate, a CSR and private key of export a certificate from a user or computer store to PFX.

	You can edit this script to change special parameters found in https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1
.PARAMETER Help
	Display the detailed information about this script
.NOTES
	File name	:	CertGUI.ps1
	Version		:	1.2
	Author		:	Harm Peter Millaard
	Requires	:	PowerShell v5.1 and up
.LINK
	https://github.com/hpmillaard/CertGUI
#>

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {Start powershell "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit}

# Create GUI
Add-Type -AN System.Windows.Forms
Add-Type -AN System.Drawing
Add-Type -AN Microsoft.VisualBasic

$Form = New-Object System.Windows.Forms.Form
$Form.Text = "Certificate PS GUI"
$Form.Size = New-Object System.Drawing.Size(480, 350)
$Form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$Form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle

function New-Label($Label, $X, $Y, $Width, $Height){
	$LabelControl = New-Object System.Windows.Forms.Label
	$LabelControl.Location = New-Object System.Drawing.Point $X, $Y
	$LabelControl.Size = New-Object System.Drawing.Size $Width, $Height
	$LabelControl.Text = $Label
	$Form.Controls.Add($LabelControl)
}
function New-TextBox($X, $Y, $Width, $Height){
	$TextBox = New-Object System.Windows.Forms.TextBox
	$TextBox.Location = New-Object System.Drawing.Point $X, $Y
	$TextBox.Size = New-Object System.Drawing.Size $Width, $Height
	$Form.Controls.Add($TextBox)
	return $TextBox
}
function New-Button($Text, $X, $Y, $Width, $Height){
	$Button = New-Object System.Windows.Forms.Button
	$Button.Location = New-Object System.Drawing.Point $X, $Y
	$Button.Size = New-Object System.Drawing.Size $Width, $Height
	$Button.Text = $Text
	$Form.Controls.Add($Button)
	return $Button
}
function New-ComboBox($X, $Y, $Width, $Height, $Items){
	$ComboBox = New-Object System.Windows.Forms.ComboBox
	$ComboBox.Location = New-Object System.Drawing.Point $X, $Y
	$ComboBox.Size = New-Object System.Drawing.Size $Width, $Height
	$ComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
	$ComboBox.Items.AddRange($Items)
	$Form.Controls.Add($ComboBox)
	return $ComboBox
}
function msgbox($Text){[System.Windows.Forms.MessageBox]::Show($Text, $Text, [System.Windows.Forms.MessageBoxButtons]::OK)}

New-Label "Friendly Name:" 5 0 200 20
$FriendlyNameTextBox = New-TextBox 210 0 250 20
New-Label "Common Name (CN):" 5 25 200 20
$CNTextBox = New-TextBox 210 25 250 20
New-Label "Organisation (O):" 5 50 200 20
$OTextBox = New-TextBox 210 50 250 20
New-Label "Organisational Unit (OU):" 5 75 200 20
$OUTextBox = New-TextBox 210 75 250 20
New-Label "City (L):" 5 100 200 20
$LTextBox = New-TextBox 210 100 250 20
New-Label "State (S):" 5 125 200 20
$STextBox = New-TextBox 210 125 250 20
New-Label "Country (C):" 5 150 200 20
$CTextBox = New-TextBox 210 150 250 20
#$CTextBox.Text = "NL"
New-Label "Subject Alternative Name (SAN) [,]:" 5 175 200 20
$SANTextBox = New-TextBox 210 175 250 20
New-Label "Expire Date:" 5 200 200 20

$DatePicker = New-Object System.Windows.Forms.DateTimePicker
$DatePicker.Location = New-Object System.Drawing.Point 210, 200
$DatePicker.Size = New-Object System.Drawing.Size 250, 20
$DatePicker.Value = (Get-Date "2030-01-01 00:00:00.000")
$Form.Controls.Add($DatePicker)

New-Label "Store:" 5 225 200 20
$Store = New-ComboBox 210 225 100 20 @("User", "Computer")
$Store.SelectedItem = "Computer"

New-Label "Key Size:" 5 250 200 20
$KeySize = New-ComboBox 210 250 100 20 @("2048", "4096")
$KeySize.SelectedItem = "4096"

function Generate-Certificate($isCSR = $false){
	$StoreLocation = if ($Store.SelectedItem -match "Computer") {"Cert:\LocalMachine\my"} else {"Cert:\CurrentUser\my"}
	$SubjectHT = @()
	If (![string]::IsNullOrEmpty($CNTextBox.Text)){$SubjectHT += "CN=$($CNTextBox.Text)"}else{msgbox "CN can't be empty";return}
	If (![string]::IsNullOrEmpty($OTextBox.Text)){$SubjectHT += "O=$($OTextBox.Text)"}
	If (![string]::IsNullOrEmpty($OUTextBox.Text)){$SubjectHT += "OU=$($OUTextBox.Text)"}
	If (![string]::IsNullOrEmpty($LTextBox.Text)){$SubjectHT += "L=$($LTextBox.Text)"}
	If (![string]::IsNullOrEmpty($STextBox.Text)){$SubjectHT += "S=$($STextBox.Text)"}
	If (![string]::IsNullOrEmpty($CTextBox.Text)){$SubjectHT += "C=$($CTextBox.Text)"}
	$Subject = $SubjectHT -Join ","

	If (!([string]::IsNullOrEmpty($SANTextBox.Text))){
		$SANs = $SANTextBox.Text -split "," | % {
			$_ = $_.Trim()
			if ($_ -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$' -or $_ -match '^[0-9a-fA-F:]+$') {"IPAddress=$_"} else {"DNS=$_"}
		}
	} else {$SANs = "DNS=$($CNTextBox.Text)"}

	if ($isCSR) {
		$F = "$ENV:TEMP\Request.inf"
$infContent = @"
[Version]
Signature="`$Windows NT$"
[NewRequest]
Subject = "$($Subject)"
Exportable = True
ProviderName = "Microsoft Software Key Storage Provider"
KeyLength = $($KeySize.SelectedItem)
KeyAlgorithm = RSA
HashAlgorithm = SHA256
MachineKeySet = True
SMIME = False
UseExistingKeySet = False
RequestType = PKCS10
#KeyUsage = 0x1			#Encipher Only
#KeyUsage = 0x2			#(Offline) CRL Signing
#KeyUsage = 0x4			#Key Certificate Signing
#KeyUsage = 0x8			#Key Agreement
#KeyUsage = 0x10		#Data Encipherment
#KeyUsage = 0x20		#Key Encipherment
#KeyUsage = 0x40		#Non Repudiation
#KeyUsage = 0x80		#Digital Signature
#KeyUsage = 0x8000		#Decipher Only
KeyUsage = 0xA0			#Digital Signature + Key Encipherment
Silent = True
[EnhancedKeyUsageExtension]
#OID=1.3.6.1.4.1.311.10.3.4	#Encrypting File System
#OID=1.3.6.1.4.1.311.10.3.12	#Document Signing
#OID=1.3.6.1.4.1.311.20.2.2	#Smart Card Logon
#OID=1.3.6.1.4.1.311.54.1.2	#Remote Desktop
#OID=1.3.6.1.4.1.311.80.1	#Document Encryption
OID=1.3.6.1.5.5.7.3.1		#Client Authentication
OID=1.3.6.1.5.5.7.3.2		#Server Authentication
#OID=1.3.6.1.5.5.7.3.3		#Code Signing
#OID=1.3.6.1.5.5.7.3.4		#Secure E-mail (S/MIME)
#OID=1.3.6.1.5.5.7.3.5		#IP Security End System
#OID=1.3.6.1.5.5.7.3.6		#IP Security Tunnel Endpoint
#OID=1.3.6.1.5.5.7.3.7		#IP Security User
#OID=1.3.6.1.5.5.7.3.8		#Time Stamping
#OID=1.3.6.1.5.5.7.3.9		#OCSP Signing
#OID=1.3.6.1.5.5.7.3.17		#IP Security Key Exchange (IKE)
#OID=1.3.6.1.5.5.7.3.21		#Secure Shell Client Authentication
#OID=1.3.6.1.5.5.7.3.22		#Secure Shell Server Authentication
#OID=2.5.29.37.0		#any Extended Key Usage
[Extensions]
2.5.29.17 = "{text}"
"@
		$infContent = ($infContent -split "`n" | ForEach-Object { $_ -replace '\s*#.*', '' } | Where-Object { $_ -ne '' }) -join "`n"
		$infContent | Set-Content $F

		$SANs | % {ac $F "_continue_ = ""$($_)&"""}

		$CSRName = $CNTextBox.Text -replace '\*','wildcard'
		$CSR = "$PSScriptRoot\$CSRName.csr"
		certreq.exe -new $F $CSR

		msgbox "CSR generated successfully and saved as $CSR!"
	} else {
		$Cert = New-SelfSignedCertificate -CertStoreLocation $StoreLocation -FriendlyName $FriendlyNameTextBox.Text -Subject $Subject -NotAfter $DatePicker.Value -KeyLength $KeySize -KeyAlgorithm $KeyAlgorithm -TextExtension ("2.5.29.17={text}" + ($SANs -join "&"))
        	if ($Cert) {msgbox "Self Signed Certificate created successfully!"}
	}
}

function Export-PFX{
	$StoreLocation = if ($Store.SelectedItem -eq "User") {"cert:\CurrentUser\my"} else {"cert:\LocalMachine\my"}
	if ((dir $StoreLocation).count -gt 0){
		$Certs = dir $StoreLocation | % {[PSCustomObject]@{CommonName = $_.SubjectName.Name.Split(',')[0] -replace '^CN=';ExpirationDate = $_.NotAfter;Thumbprint = $_.Thumbprint}} | Sort CommonName | ogv -Title "Select the certificate you want to export" -PassThru
		if ($Certs) {
			$OFD = New-Object System.Windows.Forms.SaveFileDialog
			$OFD.FileName = ($Certs.CommonName -replace '\*','wildcard') + '-' + $Certs.ExpirationDate.tostring("yyyyMMdd") + '.pfx'
			$OFD.Filter = "PFX Files (*.pfx)| *.pfx"
			$result = $OFD.ShowDialog()
			if ($result -eq [System.Windows.Forms.DialogResult]::OK) {$PFXFile = $OFD.FileName} else {msgbox "No PFX File selected.";return}
		}
		$PFXPassword = [Microsoft.VisualBasic.Interaction]::InputBox('Enter the Password for the PFX File.', 'PFX password', 'P@ssw0rd')
		if ([string]::IsNullOrWhiteSpace($PFXPassword)) {msgbox "PFX password cannot be empty.";return}

		$pwd = ConvertTo-SecureString -String $PFXPassword -Force -AsPlainText
		dir $StoreLocation\$($Cert.Thumbprint) | Export-PfxCertificate -FilePath $PFXFile -Password $pwd | Out-Null
		msgbox "Certificate is exported to $PFXFile"
	} Else {msgbox "No Certificates to export!"}
}

$CreateSelfSigned = New-Button "Create Self Signed Certificate" 5 280 205 25
$CreateSelfSigned.Add_Click({Generate-Certificate})
$Form.Controls.Add($CreateSelfSigned)

$GenerateCSR = New-Button "Generate CSR" 215 280 140 25
$GenerateCSR.Add_Click({Generate-Certificate -isCSR $true})
$Form.Controls.Add($GenerateCSR)

$ExportPFX = New-Button "Export PFX" 360 280 100 25
$ExportPFX.Add_Click({Export-PFX})
$Form.Controls.Add($ExportPFX)

$Form.ShowDialog()