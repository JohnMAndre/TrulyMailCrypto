<Serializable()> _
Public Class Key

    Public Enum KeyTypeEnum As Byte
        PublicKey = 0
        PrivateKey = 1
    End Enum

    Private m_strKey As String
    Private m_bytKeyType As KeyTypeEnum

    Public Property Key() As String
        Get
            Key = m_strKey
        End Get
        Set(ByVal Value As String)
            m_strKey = Value
        End Set
    End Property

    Public Property KeyType() As KeyTypeEnum
        Get
            KeyType = m_bytKeyType
        End Get
        Set(ByVal Value As KeyTypeEnum)
            m_bytKeyType = Value
        End Set
    End Property
End Class ' Key
