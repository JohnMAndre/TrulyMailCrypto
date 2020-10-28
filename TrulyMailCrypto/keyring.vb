'Public Class KeyRing

'    Private m_colKeys As Collection

'    Public Sub New()
'        MyBase.New()
'        m_colKeys = New Collection()
'    End Sub

'    Public Function AddKeyPair(ByRef KeyPair As KeyPair) As KeyPair
'        m_colKeys.Add(KeyPair, KeyPair.PublicKey.Label)
'        Return m_colKeys.Item(KeyPair.PublicKey.Label)
'    End Function

'    Public Function GetKeyPair(ByVal PublicKeyLabel As String) As KeyPair
'        Return m_colKeys.Item(PublicKeyLabel)
'    End Function

'    Public Sub RemoveKeyPair(ByVal PublicKeyLabel As String)
'        m_colKeys.Remove(PublicKeyLabel)
'    End Sub

'    Protected Overrides Sub Finalize()
'        m_colKeys = Nothing
'        MyBase.Finalize()
'    End Sub
'End Class ' KeyRing
