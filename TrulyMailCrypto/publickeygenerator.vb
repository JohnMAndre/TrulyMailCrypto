Imports System.Security.Cryptography

Public Class PublicKeyGenerator

    Public Function GetRSA() As System.Security.Cryptography.RSACryptoServiceProvider
        ' RSA wants to store key info in user's account
        ' we want to use the local (machine) account instead
        Const KEY_SIZE As Integer = 4096
        Dim objCspParameters As CspParameters = New CspParameters()
        objCspParameters.Flags = CspProviderFlags.UseMachineKeyStore
        Dim objRSA As RSACryptoServiceProvider = New RSACryptoServiceProvider(KEY_SIZE, objCspParameters)
        Return objRSA
        objRSA = Nothing
        objCspParameters = Nothing
    End Function

    Public Function MakeKeyPair() As KeyPair
        Dim objRSA As RSA = GetRSA()
        Dim objPublicKey As Key = New Key()
        Dim objPrivateKey As Key = New Key()
        Dim objKeyPair As New KeyPair()

        objKeyPair.PublicKey = objPublicKey
        objPublicKey.KeyType = Key.KeyTypeEnum.PublicKey
        objPublicKey.Key = objRSA.ToXmlString(False)

        objKeyPair.PrivateKey = objPrivateKey
        objPrivateKey.KeyType = Key.KeyTypeEnum.PrivateKey
        objPrivateKey.Key = objRSA.ToXmlString(True)

        Return objKeyPair

        objPublicKey = Nothing
        objPrivateKey = Nothing
        objKeyPair = Nothing
        objRSA = Nothing
    End Function

End Class ' PublicKeyGenerator
