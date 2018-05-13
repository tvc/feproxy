using System;
using System.Net.Sockets;
using System.Threading;

namespace FEProxy {
	class Proxy {
		Connection _client;
		Connection _server;

		event EventHandler<PacketEventArgs> _clientPacketReceived;
		event EventHandler<PacketEventArgs> _serverPacketReceived;

		public event EventHandler<PacketEventArgs> ClientPacketReceived {
			add { _clientPacketReceived += value; }
			remove { _clientPacketReceived -= value; }
		}

		public event EventHandler<PacketEventArgs> ServerPacketReceived {
			add { _serverPacketReceived += value; }
			remove { _serverPacketReceived -= value; }
		}

		public Proxy( Socket socket, string remoteHost, ushort remotePort ) {
			_client = new Connection( socket, true );
			_server = new Connection( remoteHost, remotePort, true );

			_client.PacketReceived += ProcessClientPacket;
			_server.PacketReceived += ProcessServerPacket;
		}

		public void Process() {
			_client.Process();
			_server.Process();
		}

		public void Disconnect() {
			_client.Disconnect();
			_server.Disconnect();
		}

		void ProcessClientPacket( object sender, PacketEventArgs e ) {
			Console.WriteLine(
				"c2s: {0:X4} {1:X4} {2}",
				e.PacketType,
				e.PacketLength,
				Formatter.FormatBuffer( e.PacketData )
			);

			while( !_server.Connected ) Thread.Sleep( 50 ); // TODO: timeout

			OnClientPacketReceived( e );

			if( e.Modified )
				Console.WriteLine(
					"c2s: {0:X4} {1:X4} {2} rewrite",
					e.PacketType,
					e.PacketLength,
					Formatter.FormatBuffer( e.PacketData )
				);

			_server.SendPacket( e.PacketType, e.PacketData );
		}

		void OnClientPacketReceived( PacketEventArgs e ) {
			_clientPacketReceived?.Invoke( this, e );
		}

		void ProcessServerPacket( object sender, PacketEventArgs e ) {
			Console.WriteLine(
				"s2c: {0:X4} {1:X4} {2}",
				e.PacketType,
				e.PacketLength,
				Formatter.FormatBuffer( e.PacketData )
			);

			while( !_client.Connected ) Thread.Sleep( 50 ); // TODO: timeout

			OnServerPacketReceived( e );

			if( e.Modified )
				Console.WriteLine(
					"s2c: {0:X4} {1:X4} {2} rewrite",
					e.PacketType,
					e.PacketLength,
					Formatter.FormatBuffer( e.PacketData )
				);

			_client.SendPacket( e.PacketType, e.PacketData );
		}

		void OnServerPacketReceived( PacketEventArgs e ) {
			_serverPacketReceived?.Invoke( this, e );
		}
	}
}