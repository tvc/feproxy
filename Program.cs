using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace FEProxy {
	class Program {
		static void Main( string[] args ) {
			ushort loginPort = UInt16.Parse( args[0] );
			ushort worldPort = UInt16.Parse( args[1] );
			string remoteHost = args[2];
			ushort remotePort = UInt16.Parse( args[3] );

			Proxy loginProxy, worldProxy;
			ProxyListener worldProxyListener;

			ProxyListener loginProxyListener = new ProxyListener( loginPort, remoteHost, remotePort );
			loginProxyListener.ProxyAccepted += ( sender, proxyEventArgs ) => {
				loginProxy = proxyEventArgs.Proxy;
				loginProxy.ServerPacketReceived += ( sender_, packetEventArgs ) => {
					if( packetEventArgs.PacketType == 0x49 ) {
						int offset = 4;
						while( packetEventArgs.PacketData[offset++] != 0 );

						string loopBack = IPAddress.Loopback.ToString();
						string worldRemoteHost = Encoding.ASCII.GetString( packetEventArgs.PacketData, 4, offset - 5 );
						ushort worldRemotePort = (ushort)BitConverter.ToUInt32( packetEventArgs.PacketData, offset );
						offset += 4;

						worldProxyListener = new ProxyListener( worldPort, worldRemoteHost, worldRemotePort );
						worldProxyListener.ProxyAccepted += ( sender__, proxyEventArgs_ ) => {
							worldProxy = proxyEventArgs_.Proxy;
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
				};
				loginProxy.Process();
			};
			loginProxyListener.Process( true );

			Console.ReadLine();
		}
	}
}
