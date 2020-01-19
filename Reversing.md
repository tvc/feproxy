# Reverse engineering

## Old offsets
```
// 81A980 send function
// 819966 send function call

// 818EC0 connect function?

// WindowProc event 0x401 linked to WSAAsyncSelect
// WindowProc calls 4F62F0 which calls net event function (connection->socket_event_cb (4D3280))

// HandleSocketEvent( struct connection* connection, DWORD event ) // event == FD_CONNECT || FD_CLOSE || FD_READ
```

## Reverse engineered connection crypto / struct
```c
/* PRNG reference: https://en.wikipedia.org/wiki/Lehmer_random_number_generator */
uint32_t GenRandomPrefix( struct connection* conn, uint8_t* buffer ) {
	const uint32_t A = 0x41A7;		// 16807
	const uint32_t M = 0x7FFFFFFF;	// 2147483647,	2^31 - 1
	const uint32_t q = 0x1F31D;		// 127773,		M / A
	const uint32_t r = 0xB16;		// 2838,		M % A

	uint32_t seed = (uint32_t)clock() + (uint32_t)conn;
	seed = A * ( seed % q ) - r * ( seed / q );
	if( seed == 0 ) seed += M;

	uint32_t end = ( seed >> 8 ) & 0x3F;
	for( uint32_t i = 0; i < end; i++ ) {
		seed = A * ( seed % q ) - r * ( seed / q );
		if( seed == 0 ) seed += M;
		buffer[i] = ( seed >> 8 ) % 0xFE;
	}
	buffer[end] = 0xFF;

	return end + 1;
}

uint32_t InitEncryptionKeys( uint32_t* enc_key_data /* in edi */, struct connection* conn, uint8_t* buffer ) {
	const uint32_t A = 0x41A7;		// 16807
	const uint32_t M = 0x7FFFFFFF;	// 2147483647,	2^31 - 1
	const uint32_t q = 0x1F31D;		// 127773,		M / A
	const uint32_t r = 0xB16;		// 2838,		M % A

	uint32_t offset = GenRandomPrefix( conn, buffer );
	uint32_t ptr = (uint32_t*)( (uint32_t)buffer + offset );

	uint32_t seed = (uint32_t)clock() + (uint32_t)conn;
	for( uint32_t i = 0; i < 4; i++ ) {
		for( uint32_t j = 0; j < 2; j++ ) {
			seed = A * ( seed % q ) - r * ( seed / q );
			if( seed == 0 ) seed += M;
		}
		enc_key_data[i] = ( ( ( seed >> 8 ) % 0x7FFF ) << 16 ) | ( ( seed >> 8 ) % 0x7FFF )
		ptr[i] = enc_key_data[i];
	}

	return offset + 16;
}

uint32_t EncryptBuffer( struct connection* conn /* in eax */, uint32_t len /* in edx */, uint8_t* src_buf, uint8_t* dst_buf ) {
	const uint32_t A = 0x41A7;		// 16807
	const uint32_t M = 0x7FFFFFFF;	// 2147483647,	2^31 - 1
	const uint32_t q = 0x1F31D;		// 127773,		M / A
	const uint32_t r = 0xB16;		// 2838,		M % A

	if( !conn )
		return 1;

	if( conn->enc_enabled && len > 0 ) {
		for( uint32_t i = 0; i < len; i++ ) {
			uint32_t seed = conn->send_key_data[conn->send_key_data[3] & 0x3];
			seed = A * ( seed % q ) - r * ( seed / q );
			if( seed == 0 ) seed += M;

			dst_buf[i] = src_buf[i] ^ (uint8_t)( ( seed >> 8 ) & 0xFF );

			conn->send_key_data[conn->send_key_data[3] & 0x3] = seed;
			conn->send_key_data[conn->send_key_data[3] & 0x3] += src_buf[i];
			conn->send_key_data[3]++;
		}
	}

	return 1;
}

uint32_t SendPacket( struct connection* conn /* in esi */ ) {
	if( conn->socket == -1 )
		return 0;

	if( conn->send_buf_off == 0 )
		return 0;

	// conn->mutex->lock();
	conn->send_time = GetTickCount();
	if( conn->send_buf_off + 1 >= conn->enc_buf_len ) {
		// conn->mutex->unlock();
		return 0;
	}

	uint32_t saved_key_data[4];
	uint32_t init_pkt_len = 0;
	int32_t sent = 0;

	if( conn->enc_enabled ) {
		conn->enc_pkt_len = 0;

		/* copy encryption keys to local vars */
		for( uint32_t i = 0; i < 4; i++ )
			saved_key_data[i] = conn->send_key_data[i];

		if( conn->send_cnt == 0.0 ) {
			conn->enc_buf[0] = 0x0B;

			if( conn->send_key_data[0] )
				OutputDebugString( "*** Faulty Key ***\n" );

			uint32_t enc_key_data[4];
			uint32_t len = InitEncryptionKeys( enc_key_data, conn, &conn->enc_buf[1] );

			conn->enc_buf_off = 1 + len;

			EncryptBuffer( conn, len, &conn->enc_buf[1], &conn->enc_buf[1] );

			init_pkt_len = conn->enc_buf_off;

			for( uint32 i = 0; i < 4; i++ )
				conn->send_key_data[i] = enc_key_data[i];

			conn->send_cnt = 1.0;
		}

		EncryptBuffer( conn, conn->send_buf_off, conn->send_buf, &conn->enc_buf[conn->enc_buf_off] );

		conn->enc_buf_off += conn->send_buf_off;

		sent = SendBuffer( conn->socket, conn->enc_buf, conn->enc_buf_off );

		if( sent != conn->enc_buf_off )
			OutputDebugString( "*** SHORT WRITE ***\n" );

		if( sent <= 0 || sent - init_pkt_len <= 0 ) {
			for( uint32_t i = 0; i < 4; i++ )
				conn->send_key_data[i] = saved_key_data[i];
			// conn->mutex->unlock();
			return sent;
		}

		sent -= init_pkt_len;
	} else {
		sent = SendBuffer( conn->socket, conn->send_buf, conn->send_buf_off );

		if( sent <= 0 ) {
			// conn->mutex->unlock();
			return sent;
		}
	}

	if( sent < conn->send_pkt_off ) {
		if( conn->enc_enabled ) {
			for( uint32_t i = 0; i < 4; i++ )
				conn->send_key_data[i] = saved_key_data[i];

			EncryptBuffer( conn, sent, conn->send_buf, conn->enc_buf );
		}

		memcpy( conn->send_buf, &conn->send_buf[sent], conn->send_buf_off - sent );
	}

	conn->send_buf_off -= sent;
	conn->send_cnt += sent;
	conn->send_cnt2 += sent;

	// conn->mutex->unlock();
	return sent;
}

uint8_t WritePacketSize( struct connection* conn /* in esi */ ) {
	if( !conn->is_socket_valid() )
		return 0;

	uint32_t send_pkt_type_size = conn->send_pkt_type_size ? 2 : 1;
	uint32_t send_pkt_len_size = conn->send_pkt_len_size ? 4 : 2;

	uint32_t send_pkt_off = conn->send_buf_off - conn->send_pkt_len;

	if( send_pkt_off + send_pkt_type_size + send_pkt_len_size >= conn->send_buf_len )
		return 0;

	conn->send_pkt_len = conn->send_pkt_len - send_pkt_type_size - send_pkt_len_size;

	if( size == 4 )
		*( (uint32_t*)( (uint32_t)conn->send_buf + send_pkt_off + send_pkt_type_size ) ) = conn->send_pkt_len;
	else
		*( (uint16_t*)( (uint32_t)conn->send_buf + send_pkt_off + send_pkt_type_size ) ) = (uint16_t)conn->send_pkt_len;

	return 1;
}

uint32_t DecryptBuffer( struct connection* conn /* in esi */, uint8_t* buf, uint32_t buf_len ) {
	const uint32_t A = 0x41A7;		// 16807
	const uint32_t M = 0x7FFFFFFF;	// 2147483647,	2^31 - 1
	const uint32_t q = 0x1F31D;		// 127773,		M / A
	const uint32_t r = 0xB16;		// 2838,		M % A

	if( !conn->enc_enabled )
		return 1;

	for( uint32_t i = 0; i < buf_len; i++ ) {
		uint32_t seed = conn->recv_key_data[conn->recv_key_data[3] & 0x3];
		seed = A * ( seed % q ) - r * ( seed / q );
		if( seed == 0 ) seed += M;

		buf[i] ^= (uint8_t)( ( seed >> 8 ) & 0xFF );

		conn->recv_key_data[conn->recv_key_data[3] & 0x3] = seed;
		conn->recv_key_data[conn->recv_key_data[3] & 0x3] += buf[i];
		conn->recv_key_data[3]++;
	}

	return 1;
}

uint32_t ReadEncryptionKeys( struct connection* conn, uint8_t* buf, uint32_t* key_data, uint32_t buf_len ) {
	int32_t recv_key_status = conn->recv_key_status;

	if( recv_key_status >= 16 )
		return buf_len;

	uint32_t remaining = buf_len;
	uint32_t i = 0;

	if( recv_key_status == -1 && buf_len > 0 ) {
		while( 1 ) {
			uint8_t byte = buf[i];

			DecryptBuffer( conn, &byte, 1 );

			remaining--;
			i++;

			if( byte == 0xFF ) {
				conn->recv_key_status = 0;
				break;
			}

			if( i >= buf_len )
				break;
		}
	}

	if( remaining && i < buf_len ) {
		do {
			if( conn->recv_key_status >= 16 )
				break;

			conn->init_recv_key_data[conn->recv_key_status] = buf[i];
			DecryptBuffer( &conn->init_recv_key_data[conn->recv_key_status], 1 );
			conn->recv_key_status++;
			i++;
			remaining--;
		} while( i < buf_len );
	}

	return remaining;
}

uint32_t RecvPacket( struct connection* conn /* in eax */ ) {
	if( conn->recv_buf_off >= conn->recv_buf_len )
		return 0;

	uint32_t avail_len = conn->recv_buf_len - conn->recv_buf_off;

	uint32_t req_len = avail_len;
	if( req_len >= 0x600 )
		req_len = 0x600;

	if( conn->unk_50 && conn->recv_buf_pos_off ) {
		if( conn->recv_buf_pos_off + conn->recv_buf_off + req_len > conn->recv_buf_len ) {
			if( conn->recv_buf_off )
				memcpy( conn->recv_buf, conn->recv_buf_pos, conn->recv_buf_off );
			conn->recv_buf_pos_off = 0;
			conn->recv_buf_pos = conn->recv_buf;
		}
	}

	int32_t recvd = recv( conn->socket, &conn->recv_buf_pos[conn->recv_buf_off], req_len );
	if( recvd == -1 )
		return -( WSAGetLastError() != 0x2733 );
	if( recvd <= 0 )
		return recvd;

	double recv_cnt = conn->recv_cnt;
	conn->recv_cnt += recvd;

	if( recv_cnt == 0.0 ) {
		if( conn->recv_buf_pos[conn->recv_buf_off] == 0x0B ) {
			conn->enc_enabled = 1;
			memcpy(
				&conn->recv_buf_pos[conn->recv_buf_off],
				&conn->recv_buf_pos[conn->recv_buf_off + 1],
				--recvd
			);
		}
	}

	if( conn->enc_enabled ) {
		if( recvd < 0 )
			return recvd;

		if( conn->recv_key_status < 16 ) {
			uint32_t result = ReadEncryptionKeys( conn, &conn->recv_buf_pos[conn->recv_buf_off], conn->init_recv_key_data, recvd );

			if( result ) {
				memcpy(
					&conn->recv_buf_pos[conn->recv_buf_off],
					&conn->recv_buf_pos[conn->recv_buf_off + recvd - result],
					result
				);
				recvd = result;
			} else
				recvd = 0;

			if( conn->recv_key_status == 16 )
				for( uint32_t i = 0; i < 4; i++ )
					conn->recv_key_data[i] = conn->init_recv_key_data[i];
		}

		if( recvd <= 0 )
			return recvd;

		DecryptBuffer( &conn->recv_buf_pos[conn->recv_buf_off], recvd );
	}

	if( recvd > 0 ) {
		conn->recv_buf_off += recvd;
		if( conn->unk_4E )
			conn->unk_14 += recvd;
		conn->recv_time = GetTickCount();
		conn->recv_cnt2 += recvd;
	}

	return recvd;
}

#pragma pack(push, 1)

struct big_struct { // constructor = 4F6320
	uint8_t unk_00[0xC8];	// 0x00
	uint32_t unk_C8;		// 0xC8
	uint8_t unk_CC[0xEB8];	// 0xCC
	float unk_F84;			// 0xF84
	uint8_t unk_F88[0xD8];	// 0xF88
}; // 0x1060
struct big_struct** big_struct = (struct big_struct**)0xE71D20;

struct connection {
	struct {
		/* uintptr_t constructor = 818CD0; */
		uintptr_t destructor;		// 0x00
		uintptr_t func_04;			// 0x04
		uintptr_t func_08;			// 0x08
		uintptr_t func_0C;			// 0x0C
		uintptr_t prepare_packet;	// 0x10 prepare_packet( uint32_t packet_type )
		uintptr_t send_packet;		// 0x14
		uintptr_t is_socket_valid;	// 0x18
		uintptr_t func_1C;			// 0x1C
	} * vtable; /* = C67DFC; */	// 0x00

	uint32_t recv_buf_off;		// 0x04
	uint32_t recv_buf_len;		// 0x08
	uint32_t recv_pkt_len;		// 0x0C
	uint32_t recv_pkt_type;		// 0x10

	uint32_t unk_14;			// 0x14

	uint32_t recv_time;			// 0x18
	uint8_t* recv_buf_pos;		// 0x1C
	uint8_t* recv_buf;			// 0x20

	uint32_t send_buf_off;		// 0x24
	uint32_t send_buf_len;		// 0x28
	uint32_t send_pkt_len;		// 0x2C
	uint32_t send_pkt_type;		// 0x30

	uint8_t unk_34[0x04];		// 0x34

	uint32_t send_time;			// 0x38
	uint8_t* send_buf;			// 0x3C

	uint8_t unk_40[0x04];		// 0x40

	uint32_t recv_buf_pos_off;	// 0x44

	uint8_t unk_48[0x04];		// 0x48

	uint8_t pkt_type_size;		// 0x4C 0 = uint8, 1 = uint16
	uint8_t pkt_len_size;		// 0x4D 0 = uint16, 1 = uint32

	uint8_t add_send_pkt_len;	// 0x4E boolean, add data length to send_pkt_len after writing in send_buf
	uint8_t unk_4F;				// 0x4F
	uint8_t unk_50;				// 0x50

	uint8_t unk_51[0x07];		// 0x51

	SOCKET socket;				// 0x58

	uint8_t unk_5C[0x44];		// 0x5C

	uint32_t keepalive_pkt_type;	// 0xA0

	uint8_t unk_A4[4];			// 0xA4

	HWND hwnd;					// 0xA8
	uintptr_t mutex;			// 0xAC

	uint8_t unk_B0[0x08];		// 0xB0

	uint32_t enk_buf_off;		// 0xB8
	uint32_t enc_buf_len;		// 0xBC
	uint8_t* enc_buf;			// 0xC0
	uint8_t enc_enabled;		// 0xC4 boolean

	uint8_t unk_C5[0x03];		// 0xC5

	uint32_t send_key_data[4];	// 0xC8 used by 819450
	uint32_t recv_key_data[4];	// 0xD8
	uint32_t init_recv_key_data[4];	// 0xE8
	int32_t init_recv_key_cnt;	// 0xF8

	uint8_t unk_FC[0x04];		// 0xFC

	double recv_cnt;			// 0x100
	double send_cnt;			// 0x108

	uintptr_t socket_event_cb;	// 0x110 = 4D3280

	uint8_t unk_114[0x04];		// 0x114

	double send_cnt2;			// 0x118
	double recv_cnt2;			// 0x120
};

struct linked_list_node {
	struct linked_list_node* prev;
	struct linked_list_node* next;
	void* ptr;
};
struct linked_list_node** conn_list = (struct linked_list_node**)0xE74348;

struct connection_container { // constructor = 4932D0
	struct connection* conn_00;	// 0x00
	struct connection* conn_04;	// 0x04

	uint8_t unk_08[0x1C];		// 0x08

	uint8_t enc_enabled;		// 0x24

	uint8_t unk_25[0x17];		// 0x25
};
struct connection_container** conn_container = (struct connection_container**)0xE71CFC;

char* username = (char*)0xD74B70;
char* password = (char*)0xD74BF0;
char* login_server = (char*)0xD74C70;
char* login_ticket = (char*)0xD74CF0;

struct PACKET_USER_LOGIN_RESPONSE {
	// s2c type 0x20
	uint32_t unk_00; // player_id? is > 0 on successful login
	uint32_t unk_04;
	uint32_t last_login_time;
	char* last_login_ip; // nul-terminated
	uint32_t failed_login_attempts;
	uint8_t profile_flags;
};

struct PACKET_USER_SYSTEM_LISTDESC {
	// s2c type = 0x4B
	uint32_t unk_00;
	uint32_t server_id;
	uint32_t user_count;
	uint32_t flags;
	char* name; // nul-terminated
	char* description; // nul-terminated
};

#pragma pack(pop)
```

## Debug output on startup
```
DebugString: "[0x00000001] Steam 0\n"
DebugString: "Class Glyph is 0\n"
DebugString: "Class Desktop is 1\n"
DebugString: "Class Row is 2\n"
DebugString: "Class Frame is 3\n"
DebugString: "Class Picture is 4\n"
DebugString: "Class View is 5\n"
DebugString: "Class GridView is 6\n"
DebugString: "Class Cell is 7\n"
DebugString: "Class MenuItem is 8\n"
DebugString: "Class Edit is 9\n"
DebugString: "Class Window is 10\n"
DebugString: "Class Group is 11\n"
DebugString: "Class Control is 12\n"
DebugString: "Class ViewCtrl is 13\n"
DebugString: "Class Button is 14\n"
DebugString: "Class CheckBox is 15\n"
DebugString: "Class RadioButton is 16\n"
DebugString: "Class ScrollBar is 17\n"
DebugString: "Class ScrollButton is 18\n"
DebugString: "Class MLEdit is 19\n"
DebugString: "Class SLEdit is 20\n"
DebugString: "Class Label is 21\n"
DebugString: "Class ListBox is 22\n"
DebugString: "Class ListBoxRow is 23\n"
DebugString: "Class Combobox is 24\n"
DebugString: "Class Combobox Listbox is 25\n"
DebugString: "Class Combobox SLedit is 26\n"
DebugString: "Class Menu is 27\n"
DebugString: "Class Dock is 28\n"
DebugString: "Class MenuButton is 29\n"
DebugString: "Class Wnd is 30\n"
DebugString: "Class DragRegion is 31\n"
DebugString: "Class FileWnd is 32\n"
DebugString: "Class Dialog is 33\n"
DebugString: "Class TreeNode is 34\n"
DebugString: "Class TreeView is 35\n"
DebugString: "Class 3DControl is 36\n"
DebugString: "Class Slider is 37\n"
DebugString: "Class Standard File Dialog is 38\n"
DebugString: "Class LabelTN is 39\n"
DebugString: "Class String is 40\n"
DebugString: "Class ColorPicker is 41\n"
DebugString: "Class Spinner is 42\n"
DebugString: "Class SpinnerSLEdit is 43\n"
DebugString: "Class SpinnerTopButton is 44\n"
DebugString: "Class SpinnerBottomButton is 45\n"
DebugString: "Class MessageBox is 46\n"
DebugString: "Class Form is 47\n"
DebugString: "Class MaskSLEdit is 48\n"
DebugString: "Class TabPage is 49\n"
DebugString: "Class TabPanel is 50\n"
DebugString: "Class Progress is 51\n"
DebugString: "Class TextBox is 52\n"
DebugString: "Class TextBoxRow is 53\n"
DebugString: "Class Simple Combobox is 54\n"
DebugString: "Class Simple Combobox Listbox is 55\n"
DebugString: "Class BrowserView is 56\n"
DebugString: "Class Browser is 57\n"
DebugString: "Class StreamView is 58\n"
DebugString: "Class Toggle is 59\n"
DebugString: "Class Calendar is 60\n"
Hardware breakpoint (dword, write) at frontend.00E71CFC (00E71CFC)!
DebugString: "[0x00000001] Connecting...\n"
DebugString: "[0x00000001] SetGlobalVariable[bool : bQuit]\n"
DebugString: "[0x00000001] Connected\n"
DebugString: "[0x00000001] Logging in...\n"
DebugString: "[0x00000009] Version is Latest Version\n"
DebugString: "[0x00000027] Logged in\n"
DebugString: "[0x00000027] --1647635 last logged in on Sat, Apr 28, 11:37 PM from IP 180.150.5.93\n"
DebugString: "[0x00000027] ProfileFlags=0x01\n"
DebugString: "[0x00000027] We are online (in lobby)\n"
DebugString: "[0x00000027] Online\n"
DebugString: "[0x00000027] Submitting System listdesc Request\n"
DebugString: "[0x0000002d] PACKET_USER_SYSTEM_LISTDESC\n"
DebugString: "[0x0000002d] Server ID=1, ucount=0, flags=0, name='Alec Masters',desc='<LifeNet File 140772 Alpha: Alec Masters>\r\nAlec Masters assumed command of the Hoover Dam Garrison after his father, General William Masters, was killed during a CHOTA attack. Masters was killed during the CHOTA Revolt, April 30th, 2152. <End File>\r\n'\n"
DebugString: "[0x0000002d] Submitting System entry request\n"
DebugString: "[0x00000038] Success choosing System\n"
DebugString: "[0x00000038] Server='173.195.33.54', Port=3001, Ticket='_ln\xAF\x08\x8C^ה[\x87@Y\xBD{\xDCTND'\n"
DebugString: "[0x00000038] Connecting to Distribution Server...\n"
DebugString: "[0x00000038] Connected\n"
DebugString: "[0x00000038] Logging to Game...\n"
DebugString: "[0x00000045] Logged to Game\n"
DebugString: "[0x00000045] We are online (in game)\n"
DebugString: "[0x00000045] Loading char view...\n"
DebugString: "[0x00000045] Loading Sky...\n"
DebugString: "[0x00000045] Loading Terrain...\n"
DebugString: "[0x00000045] Loading Thumbnails...\n"
DebugString: "[0x00000045] Loading Material pack...\n"
DebugString: "[0x00000045] Thumbnail_Find Failed: '.\\actors\\crits\\gog\\textures\\creeper_alt4.dds'\n"
DebugString: "[0x00000045] Thumbnail_Find Failed: '.\\actors\\crits\\gog\\textures\\creeper_alt5.dds'\n"
DebugString: "[0x00000045] Thumbnail_Find Failed: '.\\bolton\\-armrtextures\\twn_torso05_cc02.dds'\n"
DebugString: "[0x00000045] Loading actors DB...\n"
DebugString: "[0x00000045] Loading objects DB...\n"
DebugString: "[0x00000045] Loading player models...\n"
DebugString: "[0x00000045] Loading Actor: actors\\hmm\\hmm_rig.v3c...\n"
DebugString: "[0x00000045] ::LoadModel[0x1835DD40][0x1830EAB0] {                                          actors\\hmm\\hmm_rig.v3c}\n"
DebugString: "[0x00000045] Loading Bolton: bolton\\hmm\\ind_acc\\heads\\headlod.v3c (-1)...\n"
DebugString: "[0x00000045] ::LoadModel[0x1835D170][0x18702598] {                            bolton\\hmm\\ind_acc\\heads\\headlod.v3c}\n"
DebugString: "[0x00000045] Loading Head LOD[0x1835D170]: hmm_headlod\n"
DebugString: "[0x00000045] AddAnimToAnimSet: ubpi1 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: ubpi2 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: ubpi3 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: sbpi1 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: sbpi2 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: sbpi3 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pbpi1 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pbpi2 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pbpi3 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei1 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei10 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei11 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei2 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei3 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei4 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei5 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei6 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei7 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei8 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei9 : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwpraromud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwpraromud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwpraromlr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwpraromlr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwplaromud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwplaromud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwplaromlr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwplaromlr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwpdaromud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwpdaromud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwpdaromlr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwpdaromlr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromlr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromlud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrrarommud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromrud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromulr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrrarommlr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromdlr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwrraromlr : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwrraromud : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: hands : hmm\n"
DebugString: "[0x00000045] AddAnimToAnimSet: react : hmm\n"
DebugString: "[0x00000045] Loading Actor: actors\\hmf\\hmf_rig.v3c...\n"
DebugString: "[0x00000045] ::LoadModel[0x22B00C10][0x229F42B0] {                                          actors\\hmf\\hmf_rig.v3c}\n"
DebugString: "[0x00000045] Loading Bolton: bolton\\hmf\\ind_acc\\heads\\headlod.v3c (-1)...\n"
DebugString: "[0x00000045] ::LoadModel[0x22B00900][0x22D09218] {                            bolton\\hmf\\ind_acc\\heads\\headlod.v3c}\n"
DebugString: "[0x00000045] Loading Head LOD[0x22B00900]: hmf_headlod\n"
DebugString: "[0x00000045] AddAnimToAnimSet: ubpi1 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: ubpi2 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: ubpi3 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: sbpi1 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: sbpi2 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: sbpi3 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pbpi1 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pbpi2 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pbpi3 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei1 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei10 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei11 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei2 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei3 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei4 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei5 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei6 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei7 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei8 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uei9 : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwpraromud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwpraromud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwpraromlr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwpraromlr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwplaromud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwplaromud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwplaromlr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwplaromlr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwpdaromud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwpdaromud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwpdaromlr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwpdaromlr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromlr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromlud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrrarommud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromrud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromulr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrrarommlr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: uwrraromdlr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwrraromlr : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: pwrraromud : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: hands : hmf\n"
DebugString: "[0x00000045] AddAnimToAnimSet: react : hmf\n"
DebugString: "[0x00000045] Loading ground model...\n"
DebugString: "[0x00000045] Loading Ground Model: hmm_grnd-rig.v3c\n"
DebugString: "[0x00000045] ::LoadModel[0x24AD50F8][0x24A98470] {                                                hmm_grnd-rig.v3c}\n"
DebugString: "[0x00000045] ::LoadModel[0x24AD5168][0x24A99B50] {                                        effects\\mission_icon.v3c}\n"
DebugString: "[0x00000045] Loading Bolton: bolton\\proj\\pfx_tracer.v3c (2181)...\n"
DebugString: "[0x00000045] ::LoadModel[0x24AD5248][0x24A9A0F0] {                                      bolton\\proj\\pfx_tracer.v3c}\n"
DebugString: "Scale9Grid has negative width -4.050000\n"
DebugString: "[0x00000045] Loading Trees...\n"
DebugString: "[0x00000045] Loading Scrub...\n"
DebugString: "[0x00000045] Loading Clutter...\n"
DebugString: "[0x00000045] Done...\n"
DebugString: "[0x00000045] PACKET_USER_CHARACTER_LIST: \n"
DebugString: "[0x00000045] Slot=0, Char=Steve Nugget'\n"
DebugString: "[0x00000045] Starting Equipment=25\n"
DebugString: "[0x00000046] Loading Model: portal\\complex_sm\\cs400.v3c (3385)...\n"
DebugString: "[0x00000046] ::LoadModel[0x24AC78D8][0x2844F390] {                                     portal\\complex_sm\\cs400.v3c}\n"
DebugString: "[0x00000046] Loading Map: complexes/cs400_cselect\n"
DebugString: "[0x00000048] Loading Bolton: bolton\\hmm\\ind_acc\\hair\\hair01.v3c (1)...\n"
DebugString: "[0x00000048] ::LoadModel[0x24AC7B08][0x2844EEB0] {                              bolton\\hmm\\ind_acc\\hair\\hair01.v3c}\n"
DebugString: "[0x00000048] Loading Bolton: bolton\\hmm\\ind_acc\\heads\\head000.v3c (0)...\n"
DebugString: "[0x00000048] ::LoadModel[0x24AC7408][0x2844F810] {                            bolton\\hmm\\ind_acc\\heads\\head000.v3c}\n"
DebugString: "[0x00000048] Loading Bolton: bolton\\hmm\\ind_acc\\acc\\collar01.v3c (1)...\n"
DebugString: "[0x00000048] ::LoadModel[0x24AC7638][0x284500B0] {                             bolton\\hmm\\ind_acc\\acc\\collar01.v3c}\n"
DebugString: "[0x00000048] Adding Bolton: Char[0x00000000,       0](0x28639710) Model: 4495 (5)\n"
DebugString: "[0x00000048] Loading Bolton: bolton\\hmm\\armor\\cloth\\shirt02.v3c (4495)...\n"
DebugString: "[0x00000048] ::LoadModel[0x24AC7248][0x2844FD50] {                              bolton\\hmm\\armor\\cloth\\shirt02.v3c}\n"
DebugString: "[0x00000048]  Bolton model(slot:   6): [0x24AC7248][0x2844FD50]\n"
DebugString: "[0x00000048] Adding Bolton: Char[0x00000000,       0](0x28639710) Model: 8934 (4)\n"
DebugString: "[0x00000048] Loading Bolton: bolton\\hmm\\armor\\cloth\\ln_pants.v3c (8934)...\n"
DebugString: "[0x00000048] ::LoadModel[0x24AC7478][0x28450770] {                             bolton\\hmm\\armor\\cloth\\ln_pants.v3c}\n"
DebugString: "[0x00000048]  Bolton model(slot:  14): [0x24AC7478][0x28450770]\n"
DebugString: "[0x00000048] Adding Bolton: Char[0x00000000,       0](0x28639710) Model: 2917 (3)\n"
DebugString: "[0x00000048] Loading Bolton: bolton\\hmm\\armor\\cloth\\shoes01.v3c (2917)...\n"
DebugString: "[0x00000048] ::LoadModel[0x24AC7948][0x22E5E178] {                              bolton\\hmm\\armor\\cloth\\shoes01.v3c}\n"
DebugString: "[0x00000048]  Bolton model(slot:  17): [0x24AC7948][0x22E5E178]\n"
DebugString: "[0x00000048] Adding Bolton: Char[0x00000000,       0](0x28639710) Model: 11030 (2)\n"
DebugString: "[0x00000048] Loading Bolton: bolton\\weapons\\rifles3\\rfl_17.v3c (11030)...\n"
DebugString: "[0x00000049] Adding Object ID Low=0 model(3385) (0)\n"
DebugString: "[0x00000049] Loading Map Objects\n"
DebugString: "[0x00000049] ::LoadModel[0x24AC7868][0x22E5D758] {                               bolton\\weapons\\rifles3\\rfl_17.v3c}\n"
DebugString: "[0x00000049]  Bolton model(slot:  22): [0x24AC7868][0x22E5D758]\n"
DebugString: "[0x00000049] Loading Model: objects\\int\\lifenet\\lifenet_unit.v3c (5547)...\n"
DebugString: "[0x00000049] Adding Actor ID Low=0, Slot=0\n"
DebugString: "[0x00000049] ::LoadModel[0x24AC76A8][0x22E5D998] {                            objects\\int\\lifenet\\lifenet_unit.v3c}\n"
DebugString: "[0x00000049] Adding Bolton: Char[0x00000000,       0](0x28639710) Model: 2854 (1)\n"
DebugString: "[0x00000049] Loading Bolton: bolton\\weapons\\melee2\\axe_00.v3c (2854)...\n"
DebugString: "[0x00000049] ::LoadModel[0x24AC79B8][0x22E5D818] {                                bolton\\weapons\\melee2\\axe_00.v3c}\n"
DebugString: "[0x00000049] Failed to Load Weapon Animation: bolton\\weapons\\melee2\\axe_00_fire.v3b\n"
DebugString: "[0x00000049] Failed to Load Weapon Animation: bolton\\weapons\\melee2\\axe_00_reload.v3b\n"
DebugString: "[0x00000049]  Bolton model(slot:  27): [0x24AC79B8][0x22E5D818]\n"
DebugString: "[0x00000049] Loading Texture: .\\actors\\hmm\\textures\\hmm_body_nm.dds\n"
DebugString: "[0x00000049] Resource::LoadObjectModel [0x24AC76A8][0x22E5D998] refcount|   1|\n"
DebugString: "[0x00000049] Loading Texture: .\\portal\\-porttext\\dtl_dkiron03.dds\n"
DebugString: "[0x00000049] Resource::LoadObjectModel [0x24AC76A8][0x22E5D998] refcount|   2|\n"
DebugString: "[0x00000049] Loading Texture: .\\textures\\metal\\rustedmetal001_nm.dds\n"
DebugString: "[0x00000049] Resource::LoadObjectModel [0x24AC76A8][0x22E5D998] refcount|   3|\n"
DebugString: "[0x00000049] Loading Texture: .\\textures\\metal\\rustedmetal001.dds\n"
DebugString: "[0x00000049] Resource::LoadObjectModel [0x24AC76A8][0x22E5D998] refcount|   4|\n"
DebugString: "[0x00000049] Loading Texture: .\\textures\\metal\\rustedmetal001_sm.dds\n"
DebugString: "[0x00000049] Loading Model: objects\\particles\\steam001.v3c (8325)...\n"
DebugString: "[0x00000049] ::LoadModel[0x24AC7BE8][0x22E5D878] {                                  objects\\particles\\steam001.v3c}\n"
DebugString: "[0x00000049] Loading Texture: .\\textures\\tech\\compbox001d.dds\n"
DebugString: "[0x00000049] Loading Model: objects\\lightfix\\level\\std_spt.v3c (6209)...\n"
DebugString: "[0x00000049] ::LoadModel[0x24AC72B8][0x22E5DB18] {                              objects\\lightfix\\level\\std_spt.v3c}\n"
DebugString: "[0x00000049] Loading Texture: .\\textures\\metal\\metalfloor001_nm.dds\n"
DebugString: "[0x00000049] Resource::LoadObjectModel [0x24AC72B8][0x22E5DB18] refcount|   1|\n"
DebugString: "[0x00000049] Loading Texture: .\\textures\\metal\\metalfloor002_as.dds\n"
DebugString: "[0x00000049] Resource::LoadObjectModel [0x24AC72B8][0x22E5DB18] refcount|   2|\n"
DebugString: "[0x00000049] Loading Texture: .\\textures\\metal\\metalfloor002_sm.dds\n"
DebugString: "[0x00000049] Resource::LoadObjectModel [0x24AC72B8][0x22E5DB18] refcount|   3|\n"
DebugString: "[0x00000049] Loading Texture: .\\textures\\tech\\techceiling002_nm.dds\n"
DebugString: "[0x00000049] Loading Model: objects\\int\\lifenet\\centerconsole.v3c (8350)...\n"
DebugString: "[0x00000049] ::LoadModel[0x24AC6F38][0x22E5DBD8] {                           objects\\int\\lifenet\\centerconsole.v3c}\n"
DebugString: "[0x00000049] Loading Texture: .\\textures\\tech\\techceiling002.dds\n"
DebugString: "[0x00000049] Loading Model: objects\\int\\lifenet\\leftconsole.v3c (8353)...\n"
DebugString: "[0x00000049] ::LoadModel[0x24AC7718][0x22E5DE78] {                             objects\\int\\lifenet\\leftconsole.v3c}\n"
DebugString: "[0x00000049] Loading Texture: .\\textures\\tech\\techceiling002_sm.dds\n"
DebugString: "[0x00000049] Loading Model: objects\\int\\lifenet\\rightconsole.v3c (8357)...\n"
DebugString: "[0x00000049] ::LoadModel[0x24AC6FA8][0x22E5DCF8] {                            objects\\int\\lifenet\\rightconsole.v3c}\n"
DebugString: "[0x00000049] Loading Model: objects\\int\\lifenet\\rightconsolestand.v3c (8358)...\n"
DebugString: "[0x00000049] ::LoadModel[0x24AC7398][0x22E5DC98] {                       objects\\int\\lifenet\\rightconsolestand.v3c}\n"
DebugString: "[0x00000049] Loading Model: objects\\int\\lifenet\\leftconsolestand.v3c (8354)...\n"
DebugString: "[0x00000049] ::LoadModel[0x24AC74E8][0x22E5DC38] {                        objects\\int\\lifenet\\leftconsolestand.v3c}\n"
DebugString: "[0x00000049] Loading Model: objects\\int\\lifenet\\centerworkstation.v3c (8351)...\n"
DebugString: "[0x0000004a] ::LoadModel[0x24AC7A28][0x22E5DD58] {                       objects\\int\\lifenet\\centerworkstation.v3c}\n"
DebugString: "[0x0000004a] Loading Model: objects\\int\\lifenet\\leftworkstation.v3c (8356)...\n"
DebugString: "[0x0000004a] Adding Object ID Low=0 model(5547) (15)\n"
DebugString: "[0x0000004a] Adding Object ID Low=0 model(5547) (14)\n"
DebugString: "[0x0000004a] Adding Object ID Low=0 model(5547) (13)\n"
DebugString: "[0x0000004a] Adding Object ID Low=0 model(5547) (12)\n"
DebugString: "[0x0000004a] Adding Object ID Low=0 model(5547) (11)\n"
DebugString: "[0x0000004a] Adding Object ID Low=0 model(8325) (10)\n"
DebugString: "[0x0000004a] Adding Object ID Low=0 model(6209) (9)\n"
DebugString: "[0x0000004a] Adding Object ID Low=0 model(6209) (8)\n"
DebugString: "[0x0000004a] Adding Object ID Low=0 model(6209) (7)\n"
DebugString: "[0x0000004a] Adding Object ID Low=0 model(6209) (6)\n"
DebugString: "[0x0000004a] ::LoadModel[0x24AC71D8][0x22E5DDB8] {                         objects\\int\\lifenet\\leftworkstation.v3c}\n"
DebugString: "[0x0000004a] Loading Texture: .\\textures\\anim\\screens_genetics_al.dds\n"
DebugString: "[0x0000004a] Loading Model: objects\\int\\lifenet\\rightworkstation.v3c (8360)...\n"
DebugString: "[0x0000004a] ::LoadModel[0x24AC7A98][0x22E5E118] {                        objects\\int\\lifenet\\rightworkstation.v3c}\n"
DebugString: "[0x0000004a] Loading Texture: .\\textures\\internal\\flat_nm.dds\n"
DebugString: "[0x0000004a] Loading Texture: .\\objects\\int\\lifenet\\lifenet1_nm.dds\n"
DebugString: "[0x0000004a] Loading Texture: .\\objects\\int\\lifenet\\lifenet1.dds\n"
DebugString: "[0x0000004a] Loading Texture: .\\objects\\int\\lifenet\\lifenet2_nm.dds\n"
DebugString: "[0x0000004a] Loading Texture: .\\objects\\int\\lifenet\\lifenet2.dds\n"
DebugString: "[0x0000004b] Adding Object ID Low=0 model(8350) (7)\n"
DebugString: "[0x0000004b] Adding Object ID Low=0 model(8353) (6)\n"
DebugString: "[0x0000004b] Adding Object ID Low=0 model(8357) (5)\n"
DebugString: "[0x0000004b] Adding Object ID Low=0 model(8358) (4)\n"
DebugString: "[0x0000004b] Adding Object ID Low=0 model(8354) (3)\n"
DebugString: "[0x0000004b] Adding Object ID Low=0 model(8351) (2)\n"
DebugString: "[0x0000004b] Adding Object ID Low=0 model(8356) (1)\n"
DebugString: "[0x0000004b] Adding Object ID Low=0 model(8360) (0)\n"
DebugString: "[0x0000004b] Loading Texture: .\\objects\\int\\lifenet\\lifenet3_nm.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\objects\\int\\lifenet\\lifenet3.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\objects\\int\\lifenet\\lifenet4_nm.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\objects\\int\\lifenet\\lifenet4.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\objects\\int\\lifenet\\ln_metal01.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\metal\\metalwall011_nm.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\metal\\metalwall011.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\metal\\metalwall011_sm.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\metal\\metalwall021_nm.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\metal\\metalwall021.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\metal\\metalwall021_sm.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\concrete\\sidewalk001_nm.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\concrete\\sidewalk001.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\concrete\\sidewalk001_sm.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\metal\\metal001_nm.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\textures\\anim\\securityvid001_al.dds\n"
DebugString: "[0x0000004b] Loading Texture: .\\objects\\int\\lifenet\\console_nm.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\objects\\int\\lifenet\\console_diff.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\objects\\int\\lifenet\\toppanel.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\objects\\int\\lifenet\\lifenet_multiscreens.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\textures\\metal\\metal001.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\textures\\metal\\metal001_sm.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\textures\\internal\\sky02.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\textures\\tech\\techwall009.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\textures\\metal\\metalceiling001_nm.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\textures\\metal\\metalceiling001.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\textures\\metal\\metalceiling001_sm.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\textures\\tech\\techfloor004_nm.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\textures\\tech\\techfloor004.dds\n"
DebugString: "[0x0000004c] Loading Texture: .\\textures\\tech\\techfloor004_sm.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\bolton\\-hairtextures\\hmm_hair01.dds\n"
DebugString: "[0x0000004d] Loading 0 LTF: 072A9DD0\n"
DebugString: "[0x0000004d] Loading 2 LTF: 072A9CE0\n"
DebugString: "[0x0000004d] Loading Texture: .\\bolton\\-hairtextures\\hmm_hair01_nm.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\bolton\\-hairtextures\\hmm_hair01_sm.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\textures\\metal\\metalwall008_nm.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\textures\\metal\\metalwall008.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\textures\\metal\\metalwall008_sm.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\textures\\internal\\flat_nm.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\textures\\metal\\metalfill002.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\textures\\metal\\metalfill_sm.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\textures\\metal\\brushmetaldrt_nm.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\textures\\metal\\brushmetaldrt.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\textures\\metal\\brushmetaldrt_sm.dds\n"
DebugString: "[0x0000004d] Loading Texture: .\\textures\\misc\\hose_nm.dds\n"
DebugString: "[0x0000004d] Completing 0 LTF: 072A9DD0\n"
DebugString: "[0x0000004d] Completing 2 LTF: 072A9CE0\n"
DebugString: "[0x0000004e] Loading Texture: .\\bolton\\-armrtextures\\ln_pants.dds\n"
DebugString: "[0x0000004e] Loading Texture: .\\bolton\\-armrtextures\\ln_pants_nm.dds\n"
DebugString: "[0x0000004e] Loading Texture: .\\bolton\\-armrtextures\\shirt_sm.dds\n"
DebugString: "[0x0000004e] Loading Texture: .\\bolton\\-armrtextures\\shoes01_04.dds\n"
DebugString: "[0x0000004e] Loading Texture: .\\bolton\\-armrtextures\\shirt_basic_nm.dds\n"
DebugString: "[0x0000004e] Loading Texture: .\\bolton\\-armrtextures\\shirt02_alt1.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\bolton\\-armrtextures\\shirt02_color1.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\bolton\\-wpntextures\\flat_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\bolton\\-wpntextures\\axe_00.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\bolton\\-wpntextures\\imp_rfl_dm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\bolton\\-wpntextures\\imp_rfl_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\bolton\\-wpntextures\\imp_rfl_sm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\misc\\hose.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\misc\\hose_sm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\tech\\techceiling001_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\tech\\techceiling001.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\tech\\techceiling001_sm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\darkmetal002_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\darkmetal002.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\metal002_sm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\internal\\ap_ed.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\tech\\techfloor002_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\tech\\techfloor002.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\tech\\techfloor002_sm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\metalfloor004_at.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\metalfloor004_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\metalfloor004_sm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\ducting001_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\ducting001.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\ducting001_sm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\lvlanim\\markerlight001_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\lvlanim\\markerlight001.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\lvlanim\\markerlight001_sm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\lvlanim\\markerlight001_glow.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\metalwall023_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\metalwall023.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\metalwall023_sm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\metalbeam001_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\metalbeam001.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\metal\\metalbeam001_sm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\lvlanim\\fl_light02_inside_nm.dds\n"
DebugString: "[0x0000004f] Loading Texture: .\\textures\\lvlanim\\fl_light02_inside.dds\n"
DebugString: "[0x00000050] Loading Texture: .\\textures\\metal\\metal004_nm.dds\n"
DebugString: "[0x00000050] Loading Texture: .\\textures\\metal\\metal004.dds\n"
DebugString: "[0x00000050] Loading Texture: .\\textures\\metal\\metal004_sm.dds\n"
DebugString: "[0x00000050] Loading Texture: .\\textures\\lvlanim\\fl_light02_nm.dds\n"
DebugString: "[0x00000050] Loading Texture: .\\textures\\lvlanim\\fl_light02.dds\n"
DebugString: "[0x00000050] Loading Texture: .\\textures\\metal\\metal010_nm.dds\n"
DebugString: "[0x00000050] Loading Texture: .\\textures\\metal\\metal010.dds\n"
DebugString: "[0x00000050] Loading Texture: .\\textures\\metal\\metal010_sm.dds\n"
DebugString: "[0x00000050] Loading Texture: .\\textures\\metal\\darkmetal001_nm.dds\n"
DebugString: "[0x00000050] Loading Texture: .\\textures\\metal\\darkmetal001.dds\n"
DebugString: "[0x00000051] Loading Texture: .\\textures\\metal\\darkmetal001_sm.dds\n"
DebugString: "[0x00000051] Loading Texture: .\\textures\\metal\\metalwall015_nm.dds\n"
DebugString: "[0x00000051] Loading Texture: .\\textures\\metal\\metalwall015.dds\n"
DebugString: "[0x00000051] Loading Texture: .\\textures\\metal\\metalwall015_sm.dds\n"
DebugString: "[0x00000051] Loading Texture: .\\textures\\metal\\metalbarrel002_nm.dds\n"
DebugString: "[0x00000051] Loading Texture: .\\textures\\metal\\metalbarrel002.dds\n"
DebugString: "[0x00000051] Loading Texture: .\\textures\\metal\\metalbarrel002_sm.dds\n"
DebugString: "[0x00000051] Loading Texture: .\\textures\\tech\\techfloor001_nm.dds\n"
DebugString: "[0x00000051] Loading Texture: .\\textures\\tech\\techfloor001.dds\n"
DebugString: "[0x00000051] Loading Texture: .\\textures\\tech\\techfloor001_sm.dds\n"
DebugString: "[0x00000052] Loading Texture: .\\textures\\tech\\techwall001_nm.dds\n"
DebugString: "[0x00000052] Loading Texture: .\\textures\\tech\\techwall001.dds\n"
DebugString: "[0x00000052] Loading Texture: .\\textures\\tech\\techwall001_sm.dds\n"
DebugString: "[0x00000052] Loading Texture: .\\textures\\misc\\caution.dds\n"
DebugString: "[0x00000052] Loading Texture: .\\textures\\misc\\caution_sm.dds\n"
DebugString: "[0x00000052] Loading Texture: .\\textures\\metal\\hullplating001_nm.dds\n"
DebugString: "[0x00000052] Loading Texture: .\\textures\\metal\\hullplating002.dds\n"
DebugString: "[0x00000052] Loading Texture: .\\textures\\metal\\hullplating002_sm.dds\n"
DebugString: "[0x00000052] Loading Texture: .\\textures\\metal\\railing001_nm.dds\n"
DebugString: "[0x00000052] Loading Texture: .\\textures\\metal\\railing001.dds\n"
DebugString: "[0x00000053] Loading Texture: .\\textures\\metal\\railing001_sm.dds\n"
DebugString: "[0x00000053] Loading Texture: .\\textures\\concrete\\concretedtl001_nm.dds\n"
DebugString: "[0x00000053] Loading Texture: .\\textures\\concrete\\concretedtl001.dds\n"
DebugString: "[0x00000053] Loading Texture: .\\textures\\concrete\\concretedtl001_sm.dds\n"
DebugString: "[0x00000053] Loading Texture: .\\textures\\metal\\metalwall014_nm.dds\n"
DebugString: "[0x00000053] Loading Texture: .\\textures\\metal\\metalwall014.dds\n"
DebugString: "[0x00000053] Loading Texture: .\\textures\\metal\\metalwall014_sm.dds\n"
DebugString: "[0x00000053] Loading Texture: .\\textures\\internal\\ndalpha_al.dds\n"
DebugString: "[0x00000053] Loading Texture: .\\textures\\metal\\aluminum_ag.dds\n"
DebugString: "[0x00000053] Loading Texture: .\\textures\\tech\\techwall006_nm.dds\n"
DebugString: "[0x00000054] Loading Texture: .\\textures\\tech\\techwall006.dds\n"
DebugString: "[0x00000054] Loading Texture: .\\textures\\tech\\techwall006_sm.dds\n"
DebugString: "[0x00000054] Loading Texture: .\\textures\\tech\\techwall012_nm.dds\n"
DebugString: "[0x00000054] Loading Texture: .\\textures\\tech\\techwall012a.dds\n"
DebugString: "[0x00000054] Loading Texture: .\\textures\\tech\\techwall012_sm.dds\n"
DebugString: "[0x00000054] Loading Texture: .\\textures\\metal\\metaldetail001_nm.dds\n"
DebugString: "[0x00000054] Loading Texture: .\\textures\\metal\\metaldetail001.dds\n"
DebugString: "[0x00000054] Loading Texture: .\\textures\\metal\\metaldetail001_sm.dds\n"
DebugString: "[0x00000054] Loading Texture: .\\textures\\internal\\lightvol.dds\n"
DebugString: "[0x00000054] Loading Texture: .\\textures\\metal\\vent014.dds\n"
DebugString: "[0x00000055] Loading Texture: .\\bolton\\-hairtextures\\eyereflect.dds\n"
DebugString: "[0x00000055] Loading Texture: .\\bolton\\-hairtextures\\eyes_mouth.dds\n"
DebugString: "[0x00000055] Loading Texture: .\\bolton\\hmm\\ind_acc\\heads\\age0_nm.dds\n"
DebugString: "[0x00000055] Loading Texture: .\\bolton\\-armrtextures\\collar_nm.dds\n"
DebugString: "[0x00000055] Loading Texture: .\\bolton\\-armrtextures\\collar_dm.dds\n"
DebugString: "[0x00000055] Loading Texture: .\\bolton\\-armrtextures\\collar_scm.dds\n"
```
