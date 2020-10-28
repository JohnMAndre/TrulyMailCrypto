Imports System.Security.Cryptography
Imports System.IO
Imports System.Text

Public Class CryptographyFunctions

    Private m_objPublicKeyGenerator As PublicKeyGenerator
    Private m_objRSA As RSACryptoServiceProvider

    Public Sub New()
        MyBase.New()
        m_objPublicKeyGenerator = New PublicKeyGenerator()
        m_objRSA = m_objPublicKeyGenerator.GetRSA
        m_objPublicKeyGenerator = Nothing
    End Sub

    Protected Overrides Sub Finalize()
        MyBase.Finalize()
        m_objRSA = Nothing
    End Sub

#Region " Symetric Services "
    Public Sub EncryptFileSymetric(ByVal encryptionKey As String, ByVal filenameIn As String, ByVal filenameOut As String)
        '-- This uses RijndaelManaged provider with a key length of 128

        '-- these bytes are arbitrary, but the length is not
        Dim IV_16 As Byte() = New Byte() {215, 19, 156, 177, 24, 16, 207, 39, 19, 20, 84, 172, 214, 222, 231, 118}
        Dim realKey() As Byte = DerivePassword(encryptionKey, 16) '-- 128 / 8 = 16 bytes
        Dim provider As New System.Security.Cryptography.RijndaelManaged()

        Dim trans As ICryptoTransform = provider.CreateEncryptor(realKey, IV_16)
        Dim inpuptBytes() As Byte = System.IO.File.ReadAllBytes(filenameIn)

        Dim result() As Byte = trans.TransformFinalBlock(inpuptBytes, 0, inpuptBytes.Length)
        provider.Clear()
        trans.Dispose()

        '-- now write out encrypted file
        System.IO.File.WriteAllBytes(filenameOut, result)

    End Sub
    Public Function EncryptStringSymetric(ByVal plainText As String, ByVal encryptionKey As String) As String

        Dim bytValue() As Byte
        Dim bytKey() As Byte
        Dim bytEncoded() As Byte
        Dim bytIV() As Byte = {121, 241, 10, 1, 132, 74, 11, 39, 255, 91, 45, 78, 14, 211, 22, 62}
        Dim intLength As Integer
        Dim intRemaining As Integer
        Dim objMemoryStream As New MemoryStream()
        Dim objCryptoStream As CryptoStream
        Dim objRijndaelManaged As RijndaelManaged


        '   **********************************************************************
        '   ******  Strip any null character from string to be encrypted    ******
        '   **********************************************************************

        plainText = StripNullCharacters(plainText)

        '   **********************************************************************
        '   ******  Value must be within ASCII range (i.e., no DBCS chars)  ******
        '   **********************************************************************

        bytValue = Encoding.ASCII.GetBytes(plainText.ToCharArray)

        intLength = Len(encryptionKey)

        '   ********************************************************************
        '   ******   Encryption Key must be 256 bits long (32 bytes)      ******
        '   ******   If it is longer than 32 bytes it will be truncated.  ******
        '   ******   If it is shorter than 32 bytes it will be padded     ******
        '   ******   with upper-case Xs.                                  ****** 
        '   ********************************************************************

        If intLength >= 32 Then
            encryptionKey = Strings.Left(encryptionKey, 32)
        Else
            intLength = Len(encryptionKey)
            intRemaining = 32 - intLength
            encryptionKey = encryptionKey & Strings.StrDup(intRemaining, "X")
        End If

        bytKey = Encoding.ASCII.GetBytes(encryptionKey.ToCharArray)

        objRijndaelManaged = New RijndaelManaged()

        '   ***********************************************************************
        '   ******  Create the encryptor and write value to it after it is   ******
        '   ******  converted into a byte array                              ******
        '   ***********************************************************************

        Try

            objCryptoStream = New CryptoStream(objMemoryStream, _
              objRijndaelManaged.CreateEncryptor(bytKey, bytIV), _
              CryptoStreamMode.Write)
            objCryptoStream.Write(bytValue, 0, bytValue.Length)

            objCryptoStream.FlushFinalBlock()

            bytEncoded = objMemoryStream.ToArray
            objMemoryStream.Close()
            objCryptoStream.Close()
        Catch



        End Try

        '   ***********************************************************************
        '   ******   Return encryptes value (converted from  byte Array to   ******
        '   ******   a base64 string).  Base64 is MIME encoding)             ******
        '   ***********************************************************************

        Return Convert.ToBase64String(bytEncoded)
    End Function
    Private Function StripNullCharacters(ByVal vstrStringWithNulls As String) As String

        Dim intPosition As Integer
        Dim strStringWithOutNulls As String

        intPosition = 1
        strStringWithOutNulls = vstrStringWithNulls

        Do While intPosition > 0
            intPosition = InStr(intPosition, vstrStringWithNulls, vbNullChar)

            If intPosition > 0 Then
                strStringWithOutNulls = Left$(strStringWithOutNulls, intPosition - 1) & _
                                  Right$(strStringWithOutNulls, Len(strStringWithOutNulls) - intPosition)
            End If

            If intPosition > strStringWithOutNulls.Length Then
                Exit Do
            End If
        Loop

        Return strStringWithOutNulls

    End Function
    Public Function DecryptStringSymetric(ByVal cypherText As String, ByVal encryptionKey As String) As String

        Dim bytDataToBeDecrypted() As Byte
        Dim bytTemp() As Byte
        Dim bytIV() As Byte = {121, 241, 10, 1, 132, 74, 11, 39, 255, 91, 45, 78, 14, 211, 22, 62}
        Dim objRijndaelManaged As New RijndaelManaged()
        Dim objMemoryStream As MemoryStream
        Dim objCryptoStream As CryptoStream
        Dim bytDecryptionKey() As Byte

        Dim intLength As Integer
        Dim intRemaining As Integer
        Dim strReturnString As String = String.Empty

        '   *****************************************************************
        '   ******   Convert base64 encrypted value to byte array      ******
        '   *****************************************************************

        bytDataToBeDecrypted = Convert.FromBase64String(cypherText)

        '   ********************************************************************
        '   ******   Encryption Key must be 256 bits long (32 bytes)      ******
        '   ******   If it is longer than 32 bytes it will be truncated.  ******
        '   ******   If it is shorter than 32 bytes it will be padded     ******
        '   ******   with upper-case Xs.                                  ****** 
        '   ********************************************************************

        intLength = Len(encryptionKey)

        If intLength >= 32 Then
            encryptionKey = Strings.Left(encryptionKey, 32)
        Else
            intLength = Len(encryptionKey)
            intRemaining = 32 - intLength
            encryptionKey = encryptionKey & Strings.StrDup(intRemaining, "X")
        End If

        bytDecryptionKey = Encoding.ASCII.GetBytes(encryptionKey.ToCharArray)

        ReDim bytTemp(bytDataToBeDecrypted.Length)

        objMemoryStream = New MemoryStream(bytDataToBeDecrypted)

        '   ***********************************************************************
        '   ******  Create the decryptor and write value to it after it is   ******
        '   ******  converted into a byte array                              ******
        '   ***********************************************************************

        Try

            objCryptoStream = New CryptoStream(objMemoryStream, _
               objRijndaelManaged.CreateDecryptor(bytDecryptionKey, bytIV), _
               CryptoStreamMode.Read)

            objCryptoStream.Read(bytTemp, 0, bytTemp.Length)

            objCryptoStream.FlushFinalBlock()
            objMemoryStream.Close()
            objCryptoStream.Close()

        Catch

        End Try

        '   *****************************************
        '   ******   Return decypted value     ******
        '   *****************************************

        Return StripNullCharacters(Encoding.ASCII.GetString(bytTemp))

    End Function
    Public Sub DecryptFileSymetric(ByRef encryptionKey As String, ByVal filenameIn As String, ByVal filenameOut As String)
        '-- these bytes are arbitrary, but the length is not
        Dim IV_16 As Byte() = New Byte() {215, 19, 156, 177, 24, 16, 207, 39, 19, 20, 84, 172, 214, 222, 231, 118}
        Dim realKey() As Byte = DerivePassword(encryptionKey, 16) '-- 128 / 8 = 16
        Dim provider As New System.Security.Cryptography.RijndaelManaged()
        Dim trans As ICryptoTransform = provider.CreateDecryptor(realKey, IV_16)
        Dim inpuptBytes() As Byte = System.IO.File.ReadAllBytes(filenameIn)
        Dim result() As Byte = trans.TransformFinalBlock(inpuptBytes, 0, inpuptBytes.Length)

        '-- now write out decrypted file
        System.IO.File.WriteAllBytes(filenameOut, result)

    End Sub

#End Region
#Region " Implement Basic Asymmetric (Public/Private Key) Encryption/Decryption Services "

    ' We use Direct Encryption (PKCS#1 v1.5) - so we require MS Windows 2000 or later with high encryption pack installed.

    'sign using which key? using sender's private key
    'encrypt using which key? using recip's public key
    'Decrypt using which key? using recip's private key
    'Authenticate using which key? using sender's public key

    'Public Function SignAndEncrypt(ByRef EncryptionKeyPair As KeyPair, ByVal PlainText As String) As String
    '    ' Use Public Key to encrypt and private key to sign
    '    Return Encrypt(EncryptionKeyPair, Sign(EncryptionKeyPair, PlainText))
    'End Function

    Public Function Sign(ByRef SigningKey As Key, ByVal Text As String) As String
        Try
            'Use PrivateKey to sign
            m_objRSA.FromXmlString(SigningKey.Key)

            Dim strSignatureData As String

            strSignatureData = ByteArrayAsString(m_objRSA.SignData(StringAsByteArray(Text), System.Security.Cryptography.HashAlgorithm.Create()))

            Return Text & "<signature>" & strSignatureData & "</signature>"
        Catch ex As Exception
            Throw ex
        End Try
    End Function
    Public Function EncryptTextAsymetric(ByRef EncryptionKey As Key, ByVal PlainText As String) As String
        Try
            ' Use Public Key to encrypt
            m_objRSA.FromXmlString(EncryptionKey.Key)

            'Get Modulus Size and compare it to length of PlainText
            ' If Length of PlainText > (Modulus Size - 11), then PlainText will need to be broken into segments of size (Modulus Size - 11)
            ' Each of these segments will be encrypted separately
            '     and will return encrypted strings equal to the Modulus Size (with at least 11 bytes of padding)
            ' When decrypting, if the EncryptedText string > Modulus size, it will be split into segments of size equal to Modulus Size
            ' Each of these EncryptedText segments will be decrypted individually with the resulting PlainText segments re-assembled.

            Dim intBlockSize As Integer = GetModulusSize(EncryptionKey.Key) - 11
            Dim strEncryptedText As String = ""

            While Len(PlainText) > 0
                If Len(PlainText) > intBlockSize Then
                    strEncryptedText = strEncryptedText & EncryptBlock(Left(PlainText, intBlockSize))
                    PlainText = Right(PlainText, Len(PlainText) - intBlockSize)
                Else
                    strEncryptedText = strEncryptedText & EncryptBlock(PlainText)
                    PlainText = ""
                End If
            End While

            Return strEncryptedText
        Catch ex As Exception
            Throw ex
        End Try
    End Function
    '********************************************************
    '* DerivePassword: This takes the original plain text key
    '*                 and creates a secure key using SALT
    '********************************************************
    Private Function DerivePassword(ByVal originalPassword As String, ByVal passwordLength As Integer) As Byte()
        'Salt value used to encrypt a plain text key. Again, this can be whatever you like
        Dim SALT_BYTES As Byte() = New Byte() {142, 17, 138, 15, 228, 37, 124, 130, 46, 12, 213}
        Dim derivedBytes As New Rfc2898DeriveBytes(originalPassword, SALT_BYTES, 5)
        Return derivedBytes.GetBytes(passwordLength)
    End Function
    Public Function DecryptAndAuthenticateTextAsymetric(ByRef DecryptionKey As Key, ByVal AuthenticationKey As Key, ByVal EncryptedText As String) As String
        Try
            ' Use Private key to Decrypt and Public Key to Authenticate

            Dim strPlainText As String = ""
            Dim strSignature As String

            strPlainText = DecryptTextAsymetric(DecryptionKey, EncryptedText)

            If Authenticate(AuthenticationKey, strPlainText) Then
                strSignature = StripSignature(strPlainText)
                Return strPlainText
            Else
                'Throw new exception
                Throw New Exception("Message authentication failed.")
            End If
        Catch ex As Exception
            Throw ex
        End Try
    End Function
    



    Public Function DecryptTextAsymetric(ByRef DecryptionKey As Key, ByVal EncryptedText As String) As String
        Try
            ' Use Private Key to Decrypt - don't authenticate

            m_objRSA.FromXmlString(DecryptionKey.Key)

            ' When decrypting, if the EncryptedText string > Modulus size, it will be split into segments of size equal to Modulus Size
            ' Each of these EncryptedText segments will be decrypted individually with the resulting PlainText segments re-assembled.

            Dim intBlockSize As Integer = GetModulusSize(DecryptionKey.Key)
            Dim strPlainText As String = ""

            While Len(EncryptedText) > 0
                If Len(EncryptedText) > intBlockSize Then
                    strPlainText = strPlainText & DecryptBlock(Left(EncryptedText, intBlockSize))
                    EncryptedText = Right(EncryptedText, Len(EncryptedText) - intBlockSize)
                Else
                    strPlainText = strPlainText & DecryptBlock(EncryptedText)
                    EncryptedText = ""
                End If
            End While

            Return strPlainText
        Catch ex As Exception
            Throw ex
        End Try
    End Function
    Public Function Authenticate(ByRef AuthenticationKey As Key, ByVal SignedText As String) As Boolean
        Try
            'Use Public Key to Authenticate

            m_objRSA.FromXmlString(AuthenticationKey.Key)

            'Strip Signature from message and use it to validate message

            Dim strSignature As String = StripSignature(SignedText)

            If strSignature <> "" Then
                Return m_objRSA.VerifyData(StringAsByteArray(SignedText), System.Security.Cryptography.HashAlgorithm.Create(), StringAsByteArray(strSignature))
            Else
                Throw New Exception("Digital signature is missing or not formatted properly.")
            End If
        Catch ex As Exception
            Throw ex
        End Try
    End Function

#End Region

#Region " Helper Functions "

#Region " String <-> Byte Array Conversion Functions "
    Private Function StringAsByteArray(ByVal strIn As String) As Byte()
        Return System.Text.UnicodeEncoding.Default.GetBytes(strIn)
    End Function

    Private Function ByteArrayAsString(ByVal bytesIn As Byte()) As String
        Return System.Text.UnicodeEncoding.Default.GetString(bytesIn)
    End Function
#End Region

#Region " Block level cryptographic functions "
    Private Function EncryptBlock(ByVal strIn As String) As String
        Return ByteArrayAsString(m_objRSA.Encrypt(StringAsByteArray(strIn), False))
    End Function
    Private Function EncryptBlock(ByVal bytesIn() As Byte) As Byte()
        Return m_objRSA.Encrypt(bytesIn, False)
    End Function

    Private Function DecryptBlock(ByVal strIn As String) As String
        Return ByteArrayAsString(m_objRSA.Decrypt(StringAsByteArray(strIn), False))
    End Function
    Private Function DecryptBlock(ByVal bytesIn() As Byte) As Byte()
        Return m_objRSA.Decrypt(bytesIn, False)
    End Function
#End Region

#Region " Helper cryptographic functions "
    Private Function GetModulusSize(ByVal KeyXml As String) As Integer
        'KeySize is in Bits - so divide by 8 to get # of bytes
        Return m_objRSA.KeySize / 8
    End Function

    Private Function StripSignature(ByRef SignedText As String) As String
        ' Remove SignatureData from SignedText and Return it
        ' Assumption: signature is at end of SignedText and has <signature> and </signature> tags around it

        Dim intStartPosition As Integer
        Dim strSignatureData As String

        intStartPosition = InStr(SignedText, "<signature>", CompareMethod.Text)
        strSignatureData = Right(SignedText, Len(SignedText) - intStartPosition + 1)

        'Strip tags from signature
        strSignatureData = Replace(strSignatureData, "<signature>", "")
        strSignatureData = Replace(strSignatureData, "</signature>", "")

        'Strip signature from SignedText
        SignedText = Replace(SignedText, "<signature>" & strSignatureData & "</signature>", "", , , CompareMethod.Text)

        Return strSignatureData
    End Function
#End Region

#End Region

End Class ' CryptographyFunctions
