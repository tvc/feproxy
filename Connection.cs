using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace FEProxy {
	class Connection {
		Socket _socket;

		SocketAsyncEventArgs _recvArgs;
		SocketAsyncEventArgs _sendArgs;

		SemaphoreSlim _sendLock;
		int _sending;

		byte[] _recvBuffer;
		byte[] _sendBuffer;

		int _recvOffset;
		int _sendOffset;

		int _connected;
		bool _encrypted;

		int _recvCryptSeedCount;
		PrngXorCrypt _recvCrypt;
		PrngXorCrypt _sendCrypt;

		event EventHandler<PacketEventArgs> _packetReceived;

		long _received;
		long _sent;

		public bool Connected => _connected == 1;
		public bool Encrypted => _encrypted;

		// TODO: processing and disconnection event
		public event EventHandler<PacketEventArgs> PacketReceived {
			add { _packetReceived += value; }
			remove { _packetReceived -= value; }
		}

		Connection( bool encrypted = false ) {
			_recvBuffer = new byte[0x10000];
			_sendBuffer = new byte[0x10000];

			_recvArgs = new SocketAsyncEventArgs();
			_sendArgs = new SocketAsyncEventArgs();

			_recvArgs.SetBuffer( _recvBuffer, _recvOffset, _recvBuffer.Length - _recvOffset );
			_sendArgs.SetBuffer( _sendBuffer, 0, _sendOffset );

			_recvArgs.Completed += ProcessReceive;
			_sendArgs.Completed += ProcessSend;

			_sendLock = new SemaphoreSlim( 1, 1 );
			_sending = 0;

			_connected = 0;

			_encrypted = encrypted;
			if( _encrypted ) InitializeCrypts();
		}

		public Connection( Socket socket, bool encrypted = false ) : this( encrypted ) {
			_socket = socket;
			_socket.SetSocketOption( SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true );
			_socket.SetSocketOption( SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true );
		}

		public Connection( string host, ushort port, bool encrypted = false ) : this( encrypted ) {
			_socket = new Socket( AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp );
			_socket.Connect( host, port );
			_socket.SetSocketOption( SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true );
			_socket.SetSocketOption( SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true );
		}

		public void Process() {
			if( Interlocked.CompareExchange( ref _connected, 1, 0 ) == 1 ) return;

			if( !_socket.ReceiveAsync( _recvArgs ) )
				Task.Run( () => { ProcessReceive( _socket, _recvArgs ); } ); // Don't block main thread
		}

		public void Disconnect() {
			if( Interlocked.CompareExchange( ref _connected, 0, 1 ) == 0 ) return;

			Console.WriteLine( "Disconnecting {0} to {1}", _socket.LocalEndPoint, _socket.RemoteEndPoint );
			_socket.Disconnect( false );
			_socket.Close();
			_socket = null;
		}

		void InitializeCrypts() {
			_recvCryptSeedCount = -1;
			_recvCrypt = new PrngXorCrypt( PrngXorCryptMode.Decrypt );
			_sendCrypt = new PrngXorCrypt( PrngXorCryptMode.Encrypt );
		}

		void ProcessReceive( object sender, SocketAsyncEventArgs e ) {
			if( e.SocketError != SocketError.Success || e.BytesTransferred <= 0 ) { Disconnect(); return; }

			int received = e.BytesTransferred;
			int offset = _recvOffset;
			_recvOffset += received;

			if( _received == 0 && _recvBuffer[offset] == 0x0B ) {
				if( !_encrypted ) {
					_encrypted = true;
					InitializeCrypts();
				}

				offset++;
			}

			if( _encrypted && _recvCryptSeedCount < 16 ) {
				while( _recvCryptSeedCount == -1 && offset < _recvOffset ) {
					_recvCrypt.Process( _recvBuffer, offset, 1 );
					if( _recvBuffer[offset++] == 0xFF )
						_recvCryptSeedCount = 0;
				}

				if( _recvCryptSeedCount < 16 && offset < _recvOffset ) {
					int count = Math.Min( _recvOffset - offset, 16 - _recvCryptSeedCount );
					_recvCrypt.Process( _recvBuffer, offset, count );
					_recvCryptSeedCount += count; offset += count;
				}

				if( _recvCryptSeedCount < 16 ) {
					_received += received;
					e.SetBuffer( _recvOffset, _recvBuffer.Length - _recvOffset );
					if( !_socket.ReceiveAsync( _recvArgs ) )
						Task.Run( () => { ProcessReceive( _socket, _recvArgs ); } );
					return;
				}

				Console.WriteLine( "recv seed {0} for {1} <-- {2}", Formatter.FormatKey( _recvBuffer, offset - 16, 16 ), _socket.LocalEndPoint, _socket.RemoteEndPoint );

				_recvCrypt.SetSeed( _recvBuffer, offset - 16 );
				_recvOffset -= offset;
				Array.Copy( _recvBuffer, offset, _recvBuffer, 0, _recvOffset );
				offset = 0;
			}

			_recvCrypt.Process( _recvBuffer, offset, _recvOffset - offset );
			offset = 0;

			while( _recvOffset - offset >= 4 ) {
				ushort packetType = BitConverter.ToUInt16( _recvBuffer, offset );
				ushort packetLength = BitConverter.ToUInt16( _recvBuffer, offset + 2 );
				if( _recvOffset - offset < 4 + packetLength ) break;
				OnPacket( new PacketEventArgs( _recvBuffer, offset, 4 + packetLength ) );
				offset += 4 + packetLength;
			}

			_recvOffset -= offset;
			Array.Copy( _recvBuffer, offset, _recvBuffer, 0, _recvOffset );

			_received += received;
			e.SetBuffer( _recvOffset, _recvBuffer.Length - _recvOffset );
			if( !_socket.ReceiveAsync( _recvArgs ) )
				Task.Run( () => { ProcessReceive( _socket, _recvArgs ); } );
		}

		protected virtual void OnPacket( PacketEventArgs e ) {
			_packetReceived?.Invoke( this, e );
		}

		public void SendPacket( ushort type, byte[] data ) {
			if( _connected == 0 ) throw new Exception();

			_sendLock.Wait(); try {

			if( _sent == 0 && _encrypted && _sending == 0 /* if sending we've already done this */ ) {
				Random random = new Random();

				_sendBuffer[_sendOffset++] = 0x0B;

				int prefix = random.Next() % 64;
				for( int i = 0; i < prefix; i++ )
					_sendBuffer[_sendOffset++] = (byte)( random.Next() % 256 );
				_sendBuffer[_sendOffset++] = 0xFF;

				for( int i = 0; i < 16; i++ )
					_sendBuffer[_sendOffset++] = (byte)( random.Next() % 256 );
				
				byte[] seed = new byte[16];
				Array.Copy( _sendBuffer, _sendOffset - 16, seed, 0, 16 );

				Console.WriteLine( "send seed {0} for {1} --> {2}", Formatter.FormatKey( seed ), _socket.LocalEndPoint, _socket.RemoteEndPoint );

				int length = prefix + 1 + 16;
				_sendCrypt.Process( _sendBuffer, _sendOffset - length, length );

				_sendCrypt.SetSeed( seed );
			}

			if( _sendBuffer.Length - _sendOffset < 4 + data.Length ) throw new Exception(); // TODO: fix me

			_sendCrypt.Process( BitConverter.GetBytes( type ), 0, _sendBuffer, _sendOffset, sizeof( ushort ) );
			_sendOffset += 2;
			_sendCrypt.Process( BitConverter.GetBytes( (ushort)data.Length ), 0, _sendBuffer, _sendOffset, sizeof( ushort ) );
			_sendOffset += 2;
			_sendCrypt.Process( data, 0, _sendBuffer, _sendOffset, data.Length );
			_sendOffset += data.Length;

			if( Interlocked.CompareExchange( ref _sending, 1, 0 ) == 0 ) {
				_sendArgs.SetBuffer( _sendBuffer, 0, _sendOffset );
				if( !_socket.SendAsync( _sendArgs ) )
					Task.Run( () => { ProcessSend( _socket, _sendArgs ); } );
			}

			} finally { _sendLock.Release(); }
		}

		void ProcessSend( object sender, SocketAsyncEventArgs e ) {
			if( e.SocketError != SocketError.Success || e.BytesTransferred <= 0 ) { Disconnect(); return; }

			int sent = e.BytesTransferred;

			_sendLock.Wait(); try {

			_sent += sent;

			_sendOffset -= sent;
			Array.Copy( _sendBuffer, sent, _sendBuffer, 0, _sendOffset );

			if( _sendOffset > 0 ) {
				e.SetBuffer( _sendBuffer, 0, _sendOffset );
				if( !_socket.SendAsync( _sendArgs ) )
					Task.Run( () => { ProcessSend( _socket, _sendArgs ); } );
			} else {
				Interlocked.Exchange( ref _sending, 0 );
			}

			} finally { _sendLock.Release(); }
		}
	}
}