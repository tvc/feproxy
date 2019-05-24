using System;
using System.IO;
using System.Net;
using System.Text;

namespace FEProxy {
	class Program {
		static Proxy loginProxy, worldProxy;
		static ProxyListener loginProxyListener, worldProxyListener;

		static string remoteHost;
		static ushort loginPort, worldPort, remotePort;

		static void LoginServerPacketReceived( object _, PacketEventArgs packetEventArgs ) {
			if( packetEventArgs.PacketType == 0x49 ) {
				int offset = 4;
				while( packetEventArgs.PacketData[offset++] != 0 );

				string loopBack = IPAddress.Loopback.ToString();
				string worldRemoteHost = Encoding.ASCII.GetString( packetEventArgs.PacketData, 4, offset - 5 );
				ushort worldRemotePort = (ushort)BitConverter.ToUInt32( packetEventArgs.PacketData, offset );
				offset += 4;

				worldProxyListener = new ProxyListener( worldPort, worldRemoteHost, worldRemotePort );
				worldProxyListener.ProxyAccepted += ( __, proxyEventArgs ) => {
					worldProxy = proxyEventArgs.Proxy;
					worldProxy.Process();
				};
				worldProxyListener.Process( true );

				using( MemoryStream stream = new MemoryStream() ) {
					stream.Write( packetEventArgs.PacketData, 0, 4 );
					stream.Write( Encoding.ASCII.GetBytes( loopBack ), 0, Encoding.ASCII.GetByteCount( loopBack ) );
					stream.WriteByte( 0 );
					stream.Write( BitConverter.GetBytes( (uint)worldPort ), 0, 4 );
					stream.Write( packetEventArgs.PacketData, offset, packetEventArgs.PacketLength - offset );

					byte[] buffer = new byte[stream.Length];
					Array.Copy( stream.GetBuffer(), buffer, buffer.Length );

					packetEventArgs.SetPacketData( buffer );
				}
			}
		}

		static void Main( string[] args ) {
			loginPort = UInt16.Parse( args[0] );
			worldPort = UInt16.Parse( args[1] );
			remoteHost = args[2];
			remotePort = UInt16.Parse( args[3] );

			loginProxyListener = new ProxyListener( loginPort, remoteHost, remotePort );
			loginProxyListener.ProxyAccepted += ( _, proxyEventArgs ) => {
				loginProxy = proxyEventArgs.Proxy;
				loginProxy.ServerPacketReceived += LoginServerPacketReceived;
				loginProxy.Process();
			};
			loginProxyListener.Process( true );

			Console.ReadLine();
		}
	}
}
