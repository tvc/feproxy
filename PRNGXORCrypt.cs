using System;

namespace FEProxy {
	enum PrngXorCryptMode {
		Encrypt,
		Decrypt
	}

	class PrngXorCrypt : ICloneable {
		PrngXorCryptMode _cryptMode;

		uint[] _seeds;

		public PrngXorCryptMode CryptMode => _cryptMode;

		public PrngXorCrypt( PrngXorCryptMode cryptMode ) {
			_cryptMode = cryptMode;
			_seeds = new uint[] { 0, 0, 0, 0 };
		}

		public object Clone() {
			PrngXorCrypt clone = new PrngXorCrypt( _cryptMode );
			for( int i = 0; i < _seeds.Length; i++ )
				clone._seeds[i] = _seeds[i];
			return clone;
		}

		public void SetSeed( byte[] buffer, int offset ) {
			#if DEBUG
			if( buffer == null ) throw new ArgumentNullException( nameof( buffer ) );
			if( buffer.Length < _seeds.Length * sizeof( uint ) ) throw new ArgumentOutOfRangeException( nameof( buffer ) );
			if( offset < 0 || offset > buffer.Length || offset > buffer.Length - _seeds.Length * sizeof( uint ) )
				throw new ArgumentOutOfRangeException( nameof( offset ) );
			#endif

			for( int i = 0; i < _seeds.Length; i++ )
				_seeds[i] = BitConverter.ToUInt32( buffer, offset + i * sizeof( uint ) );
		}

		public void SetSeed( byte[] seed ) {
			#if DEBUG
			if( seed == null ) throw new ArgumentNullException( nameof( seed ) );
			if( seed.Length != _seeds.Length * sizeof( uint ) ) throw new ArgumentOutOfRangeException( nameof( seed ) );
			#endif

			SetSeed( seed, 0 );
		}

		public void Process( byte[] inBuffer, int inOffset, byte[] outBuffer, int outOffset, int count ) {
			/* PRNG reference: https://en.wikipedia.org/wiki/Lehmer_random_number_generator */

			#if DEBUG
			if( inBuffer == null ) throw new ArgumentNullException( nameof( inBuffer ) );
			if( outBuffer == null ) throw new ArgumentNullException( nameof( outBuffer ) );
			if( inOffset < 0 || inOffset > inBuffer.Length ) throw new ArgumentOutOfRangeException( nameof( inOffset ) );
			if( outOffset < 0 || outOffset > outBuffer.Length ) throw new ArgumentOutOfRangeException( nameof( outOffset ) );
			if( count < 0 || count > inBuffer.Length - inOffset || count > outBuffer.Length - outOffset )
				throw new ArgumentOutOfRangeException( nameof( count ) );
			#endif

			const uint A = 0x41A7;
			const uint M = 0x7FFFFFFF;
			const uint q = 0x1F31D;
			const uint r = 0xB16;

			for( int i = 0; i < count; i++ ) {
				uint seed = _seeds[_seeds[3] & 0x3];
				seed = A * ( seed % q ) - r * ( seed / q );
				if( seed == 0 )
					seed += M;

				if( _cryptMode == PrngXorCryptMode.Encrypt ) {
					_seeds[_seeds[3] & 0x3] = seed;
					_seeds[_seeds[3] & 0x3] += inBuffer[inOffset + i]; // Add plaintext byte value
					_seeds[3]++;
				}

				outBuffer[outOffset + i] = (byte)( inBuffer[inOffset + i] ^ seed >> 8 & 0xFF );

				if( _cryptMode == PrngXorCryptMode.Decrypt ) {
					_seeds[_seeds[3] & 0x3] = seed;
					_seeds[_seeds[3] & 0x3] += outBuffer[outOffset + i]; // Add plaintext byte value
					_seeds[3]++;
				}
			}
		}

		public void Process( byte[] buffer, int offset, int count ) => Process( buffer, offset, buffer, offset, count );
	}
}
