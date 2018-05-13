using System;

namespace FEProxy {
	class PacketEventArgs : EventArgs {
		ushort _type;
		byte[] _data;
		bool _modified;

		public ushort PacketType => _type;
		public byte[] PacketData => _data;
		public int PacketLength => _data.Length;
		public bool Modified => _modified;

		public PacketEventArgs( byte[] buffer, int offset, int count ) {
			if( count < 4 ) throw new Exception();
			_type = BitConverter.ToUInt16( buffer, offset );
			int length = BitConverter.ToUInt16( buffer, offset + 2 );
			if( count < 4 + length ) throw new Exception();
			_data = new byte[length];
			Buffer.BlockCopy( buffer, offset + 4, _data, 0, length );
		}

		public PacketEventArgs( ushort type, byte[] data ) {
			_type = type;
			_data = new byte[data.Length];
			Buffer.BlockCopy( data, 0, _data, 0, _data.Length );
		}

		public void SetPacketData( byte[] data ) {
			_data = data;
			_modified = true;
		}
	}
}