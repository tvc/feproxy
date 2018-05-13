using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace FEProxy {
	class ProxyListener {
		Socket _socket;

		string _remoteHost;
		ushort _remotePort;

		SocketAsyncEventArgs _acceptArgs;

		event EventHandler<ProxyEventArgs> _proxyAccepted;

		public event EventHandler<ProxyEventArgs> ProxyAccepted {
			add { _proxyAccepted += value; }
			remove { _proxyAccepted -= value; }
		}
		
		public ProxyListener( IPAddress localAddress, ushort localPort, string remoteHost, ushort remotePort ) {
			_socket = new Socket( AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp );
			_socket.Bind( new IPEndPoint( localAddress, localPort ) );
			_socket.Listen( 5 );

			_remoteHost = remoteHost;
			_remotePort = remotePort;

			_acceptArgs = new SocketAsyncEventArgs();
			_acceptArgs.Completed += ProcessAccept;
		}

		public ProxyListener( ushort localPort, string remoteHost, ushort remotePort ) :
			this( IPAddress.Any, localPort, remoteHost, remotePort ) {}

		public void Process( bool oneShot = false ) {
			_acceptArgs.UserToken = oneShot;
			if( !_socket.AcceptAsync( _acceptArgs ) )
				Task.Run( () => { ProcessAccept( _socket, _acceptArgs ); } );
		}

		public void Close() {
			_socket.Close();
		}

		void ProcessAccept( object sender, SocketAsyncEventArgs e ) {
			if( e.SocketError != SocketError.Success || e.AcceptSocket == null ) { Close(); return; }

			OnProxyAccepted( new ProxyEventArgs( new Proxy( e.AcceptSocket, _remoteHost, _remotePort ) ) );

			if( (bool)e.UserToken ) return;

			_acceptArgs.AcceptSocket = null;
			if( !_socket.AcceptAsync( _acceptArgs ) )
				Task.Run( () => { ProcessAccept( _socket, _acceptArgs ); } );
		}

		void OnProxyAccepted( ProxyEventArgs e ) {
			_proxyAccepted?.Invoke( this, e );
		}
	}
}