<Serializable()> _
Public Class KeyPair

    Private m_strPublicKey As Key
    Private m_strPrivateKey As Key

    Public Property PublicKey() As Key
        Get
            PublicKey = m_strPublicKey
        End Get
        Set(ByVal Value As Key)
            m_strPublicKey = Value
        End Set
    End Property

    Public Property PrivateKey() As Key
        Get
            PrivateKey = m_strPrivateKey
        End Get
        Set(ByVal Value As Key)
            m_strPrivateKey = Value
        End Set
    End Property

End Class ' KeyPair
