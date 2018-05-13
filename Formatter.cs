using System.Text;

namespace FEProxy {
	class Formatter {
		public static string FormatBuffer( byte[] buffer, int offset, int length ) {
			StringBuilder stringBuilder = new StringBuilder( length * 4 );

			for( int i = offset; i < offset + length; i++ ) {
				if( buffer[i] >= 0x20 && buffer[i] < 0x7F )
					stringBuilder.Append( (char)buffer[i] );
				else
					stringBuilder.AppendFormat( "\\x{0:X2}", buffer[i] );
			}

			return stringBuilder.ToString();
		}
		public static string FormatBuffer( byte[] buffer ) => FormatBuffer( buffer, 0, buffer.Length );

		public static string FormatKey( byte[] buffer, int offset, int length ) {
			StringBuilder stringBuilder = new StringBuilder( length * 2 );

			for( int i = offset; i < offset + length; i++ )
				stringBuilder.AppendFormat( "{0:X2}", buffer[i] );

			return stringBuilder.ToString();
		}
		public static string FormatKey( byte[] buffer ) => FormatKey( buffer, 0, buffer.Length );
	}
}