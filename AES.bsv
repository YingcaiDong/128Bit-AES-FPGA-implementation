package AESchange;

	interface Ifc_main_type;
		method Action loadInput(Bit#(32) dIn, int addr);
		method Action importKey(Bit#(32) imKey, int addr);
		method Action loadDestate(Bit#(32) des, int addr);
		method Action check_signal(int signal);
		method int checkpoint ();
		method int output_signal();
		method Bit#(8) output_state(int i, int j);	
		method Bit#(8) output_result(int i, int j);
		method Bit#(32) checkTemp();
	endinterface: Ifc_main_type

	(*synthesize*)
	module mkTb (Ifc_main_type);


///////////////////////////////////////////////////////////////////////////////////////////////////
//			Essential data										     
///////////////////////////////////////////////////////////////////////////////////////////////////

		//------------------------------------- Encryption part -----------------------------------------//

		Reg#(Bit#(8)) state[4][4];			//Used to store encryption intermediate value

		Reg#(Bit#(8)) keym[4][4];			//Used to store the value of the cipher key

		Reg#(Bit#(8)) sbox[16][16];
		Bit#(8) s_box[16][16]={
			// 0     1    2      3     4     5     6     7     8     9     a     b     c     d     e     f */
			{8'h63,8'h7c,8'h77,8'h7b,8'hf2,8'h6b,8'h6f,8'hc5,8'h30,8'h01,8'h67,8'h2b,8'hfe,8'hd7,8'hab,8'h76}, // 0
	   	 	{8'hca,8'h82,8'hc9,8'h7d,8'hfa,8'h59,8'h47,8'hf0,8'had,8'hd4,8'ha2,8'haf,8'h9c,8'ha4,8'h72,8'hc0}, // 1
	 	 	{8'hb7,8'hfd,8'h93,8'h26,8'h36,8'h3f,8'hf7,8'hcc,8'h34,8'ha5,8'he5,8'hf1,8'h71,8'hd8,8'h31,8'h15}, // 2
	  		{8'h04,8'hc7,8'h23,8'hc3,8'h18,8'h96,8'h05,8'h9a,8'h07,8'h12,8'h80,8'he2,8'heb,8'h27,8'hb2,8'h75}, // 3
	  		{8'h09,8'h83,8'h2c,8'h1a,8'h1b,8'h6e,8'h5a,8'ha0,8'h52,8'h3b,8'hd6,8'hb3,8'h29,8'he3,8'h2f,8'h84}, // 4
	  		{8'h53,8'hd1,8'h00,8'hed,8'h20,8'hfc,8'hb1,8'h5b,8'h6a,8'hcb,8'hbe,8'h39,8'h4a,8'h4c,8'h58,8'hcf}, // 5
	  		{8'hd0,8'hef,8'haa,8'hfb,8'h43,8'h4d,8'h33,8'h85,8'h45,8'hf9,8'h02,8'h7f,8'h50,8'h3c,8'h9f,8'ha8}, // 6
	  		{8'h51,8'ha3,8'h40,8'h8f,8'h92,8'h9d,8'h38,8'hf5,8'hbc,8'hb6,8'hda,8'h21,8'h10,8'hff,8'hf3,8'hd2}, // 7
			{8'hcd,8'h0c,8'h13,8'hec,8'h5f,8'h97,8'h44,8'h17,8'hc4,8'ha7,8'h7e,8'h3d,8'h64,8'h5d,8'h19,8'h73}, // 8
 	   		{8'h60,8'h81,8'h4f,8'hdc,8'h22,8'h2a,8'h90,8'h88,8'h46,8'hee,8'hb8,8'h14,8'hde,8'h5e,8'h0b,8'hdb}, // 9
			{8'he0,8'h32,8'h3a,8'h0a,8'h49,8'h06,8'h24,8'h5c,8'hc2,8'hd3,8'hac,8'h62,8'h91,8'h95,8'he4,8'h79}, // a
	 		{8'he7,8'hc8,8'h37,8'h6d,8'h8d,8'hd5,8'h4e,8'ha9,8'h6c,8'h56,8'hf4,8'hea,8'h65,8'h7a,8'hae,8'h08}, // b
	 		{8'hba,8'h78,8'h25,8'h2e,8'h1c,8'ha6,8'hb4,8'hc6,8'he8,8'hdd,8'h74,8'h1f,8'h4b,8'hbd,8'h8b,8'h8a}, // c
 			{8'h70,8'h3e,8'hb5,8'h66,8'h48,8'h03,8'hf6,8'h0e,8'h61,8'h35,8'h57,8'hb9,8'h86,8'hc1,8'h1d,8'h9e}, // d
 			{8'he1,8'hf8,8'h98,8'h11,8'h69,8'hd9,8'h8e,8'h94,8'h9b,8'h1e,8'h87,8'he9,8'hce,8'h55,8'h28,8'hdf}, // e
			{8'h8c,8'ha1,8'h89,8'h0d,8'hbf,8'he6,8'h42,8'h68,8'h41,8'h99,8'h2d,8'h0f,8'hb0,8'h54,8'hbb,8'h16}  // f
			};
		
		Reg#(Bit#(8)) rcon[4][10];
		Bit#(8) r_con[4][10]={
			// 0      1      2      3 
			{8'h01, 8'h02, 8'h04, 8'h08, 8'h10, 8'h20, 8'h40, 8'h80, 8'h1b, 8'h36}, // 0
			{8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00}, // 1
			{8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00}, // 2
			{8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00, 8'h00}  // 3
			};
		
		Reg#(Bit#(8)) mix[4][4];
		Bit#(8) m_ix[4][4] = {
			// 0      1      2      3
			{8'h02, 8'h03, 8'h01, 8'h01}, // 0
			{8'h01, 8'h02, 8'h03, 8'h01}, // 1
			{8'h01, 8'h01, 8'h02, 8'h03}, // 2
			{8'h03, 8'h01, 8'h01, 8'h02}  // 3
			};

		//---------------------------------- Decipher part -----------------------------------------//

		Reg#(Bit#(8)) resultt[4][4];			//Used to store decipher intermediate data
		
		Reg#(Bit#(8)) invsbox[16][16];
		Bit#(8) inv_sbox[16][16]={
    		{8'h52,8'h09,8'h6a,8'hd5,8'h30,8'h36,8'ha5,8'h38,8'hbf,8'h40,8'ha3,8'h9e,8'h81,8'hf3,8'hd7,8'hfb}, /*0*/
    		{8'h7c,8'he3,8'h39,8'h82,8'h9b,8'h2f,8'hff,8'h87,8'h34,8'h8e,8'h43,8'h44,8'hc4,8'hde,8'he9,8'hcb}, /*1*/
    		{8'h54,8'h7b,8'h94,8'h32,8'ha6,8'hc2,8'h23,8'h3d,8'hee,8'h4c,8'h95,8'h0b,8'h42,8'hfa,8'hc3,8'h4e}, /*2*/
    		{8'h08,8'h2e,8'ha1,8'h66,8'h28,8'hd9,8'h24,8'hb2,8'h76,8'h5b,8'ha2,8'h49,8'h6d,8'h8b,8'hd1,8'h25}, /*3*/
    		{8'h72,8'hf8,8'hf6,8'h64,8'h86,8'h68,8'h98,8'h16,8'hd4,8'ha4,8'h5c,8'hcc,8'h5d,8'h65,8'hb6,8'h92}, /*4*/
    		{8'h6c,8'h70,8'h48,8'h50,8'hfd,8'hed,8'hb9,8'hda,8'h5e,8'h15,8'h46,8'h57,8'ha7,8'h8d,8'h9d,8'h84}, /*5*/
    		{8'h90,8'hd8,8'hab,8'h00,8'h8c,8'hbc,8'hd3,8'h0a,8'hf7,8'he4,8'h58,8'h05,8'hb8,8'hb3,8'h45,8'h06}, /*6*/
    		{8'hd0,8'h2c,8'h1e,8'h8f,8'hca,8'h3f,8'h0f,8'h02,8'hc1,8'haf,8'hbd,8'h03,8'h01,8'h13,8'h8a,8'h6b}, /*7*/
    		{8'h3a,8'h91,8'h11,8'h41,8'h4f,8'h67,8'hdc,8'hea,8'h97,8'hf2,8'hcf,8'hce,8'hf0,8'hb4,8'he6,8'h73}, /*8*/
    		{8'h96,8'hac,8'h74,8'h22,8'he7,8'had,8'h35,8'h85,8'he2,8'hf9,8'h37,8'he8,8'h1c,8'h75,8'hdf,8'h6e}, /*9*/
    		{8'h47,8'hf1,8'h1a,8'h71,8'h1d,8'h29,8'hc5,8'h89,8'h6f,8'hb7,8'h62,8'h0e,8'haa,8'h18,8'hbe,8'h1b}, /*a*/
    		{8'hfc,8'h56,8'h3e,8'h4b,8'hc6,8'hd2,8'h79,8'h20,8'h9a,8'hdb,8'hc0,8'hfe,8'h78,8'hcd,8'h5a,8'hf4}, /*b*/
    		{8'h1f,8'hdd,8'ha8,8'h33,8'h88,8'h07,8'hc7,8'h31,8'hb1,8'h12,8'h10,8'h59,8'h27,8'h80,8'hec,8'h5f}, /*c*/
    		{8'h60,8'h51,8'h7f,8'ha9,8'h19,8'hb5,8'h4a,8'h0d,8'h2d,8'he5,8'h7a,8'h9f,8'h93,8'hc9,8'h9c,8'hef}, /*d*/
    		{8'ha0,8'he0,8'h3b,8'h4d,8'hae,8'h2a,8'hf5,8'hb0,8'hc8,8'heb,8'hbb,8'h3c,8'h83,8'h53,8'h99,8'h61}, /*e*/
    		{8'h17,8'h2b,8'h04,8'h7e,8'hba,8'h77,8'hd6,8'h26,8'he1,8'h69,8'h14,8'h63,8'h55,8'h21,8'h0c,8'h7d}  /*f*/
			};

		Reg#(Bit#(8)) invmix[4][4];
		Bit#(8) inv_mix[4][4] = {
			{8'h0e, 8'h0b, 8'h0d, 8'h09},
			{8'h09, 8'h0e, 8'h0b, 8'h0d},
			{8'h0d, 8'h09, 8'h0e, 8'h0b},
			{8'h0b, 8'h0d, 8'h09, 8'h0e}
			};


///////////////////////////////////////////////////////////////////////////////////////////////////
//			Declear variables									     
///////////////////////////////////////////////////////////////////////////////////////////////////
		Reg#(Bit#(8)) keySched[4][44];				// Used to store the round key
									// the  round key can be devide into 11 groups
									// each group contains 4 by 4 elements
		
		Reg#(Bit#(8)) mReword[4][10];				// Used to store every first column of the each group

		Reg#(int) step <- mkReg(700);				// The state of the rules
		
		//-------------------------------- Generate round key -----------------------------------//
		Reg#(int) i_rk <- mkReg(0);
		Reg#(Bit#(8)) tempFirstBit <- mkRegU;
		Reg#(Bit#(8)) tempShiftBits[4][1];
		Reg#(int) z_rk <- mkReg(0);
		Reg#(Bit#(8)) tempSub <- mkRegU;
		Reg#(Bit#(4)) tempSub1 <- mkRegU;
		Reg#(Bit#(4)) tempSub2 <- mkRegU;
		Reg#(Bit#(8)) tempRcon <- mkRegU;
		Reg#(Bit#(8)) tempSubOne[4][1];				// Fetch the previous row
		Reg#(Bit#(8)) tempSubFour[4][1];			// Fetch the row which row number is 4 smaller than the current one
		Reg#(int) k_rk <- mkReg(1);
		Reg#(int) p_rk <- mkReg(0);

		//------------------------------------- AES encryption -----------------------------------------//
		Reg#(int) a <- mkReg(0);

		//---------------------------- AES encrypton: Byte substitution -------------------------------//
		Reg#(int) b <- mkReg(0);
		Reg#(int) c <- mkReg(0);
		Reg#(Bit#(8)) tSub <- mkRegU;
		Reg#(Bit#(4)) tSub1 <- mkRegU;
		Reg#(Bit#(4)) tSub2 <- mkRegU;

		//------------------------------- AES encrypton: Shift rows -----------------------------------//
		Reg#(Bit#(8)) tempshift1 <- mkRegU;
		Reg#(Bit#(8)) tempshift2 <- mkRegU;
		Reg#(Bit#(8)) tempshift3 <- mkRegU;
		Reg#(Bit#(8)) tempshift4 <- mkRegU;
		Reg#(Bit#(8)) tempshift5 <- mkRegU;
		Reg#(Bit#(8)) tempshift6 <- mkRegU;
		Reg#(Bit#(8)) tempshift7 <- mkRegU;

		//------------------------------- AES encrypton: Mixcolumn -----------------------------------//
		Reg#(int) d <- mkReg(0);
		Reg#(int) e <- mkReg(0);
		Reg#(int) f <- mkReg(0);
		Reg#(Bit#(8)) tempstate[4][4];
		Reg#(Bit#(8)) tempmix <- mkRegU;
		Reg#(Bit#(8)) tempfile <- mkRegU;
		Reg#(Bit#(8)) tempfile1 <- mkRegU;

		//----------------------------- AES encrypton: Add round key ---------------------------------//
		Reg#(int) h <- mkReg(0);
		Reg#(int) g <- mkReg(0);

		//------------------------------------- AES decipher -----------------------------------------//
		Reg#(int) k <- mkReg(0);
		Reg#(Bit#(8)) tshift1 <- mkRegU;
		Reg#(Bit#(8)) tshift2 <- mkRegU;
		Reg#(Bit#(8)) tshift3 <- mkRegU;
		Reg#(Bit#(8)) tshift4 <- mkRegU;
		Reg#(Bit#(8)) tshift5 <- mkRegU;
		Reg#(Bit#(8)) tshift6 <- mkRegU;
		Reg#(Bit#(8)) tshift7 <- mkRegU;
		Reg#(Bit#(8)) tshift8 <- mkRegU;
		Reg#(Bit#(8)) tshift11 <- mkRegU;
		Reg#(Bit#(8)) tshift22 <- mkRegU;
		Reg#(Bit#(8)) tshift33 <- mkRegU;
		Reg#(Bit#(8)) tshift44 <- mkRegU;

		//----------------------- AES decipher: Inverse byte substitution ---------------------------//
		Reg#(int) bz <- mkReg(0);
		Reg#(int) cz <- mkReg(0);
		Reg#(Bit#(8)) tSb <- mkRegU;
		Reg#(Bit#(4)) tSb1 <- mkRegU;
		Reg#(Bit#(4)) tSb2 <- mkRegU;

		//------------------------ AES decipher: Inverse add round key ------------------------------//
		Reg#(int) gz <- mkReg(0);
		Reg#(int) hz <- mkReg(0);

		//-------------------------- AES decipher: Inverse mixcolumn -------------------------------//
		Reg#(Bit#(8)) invtempstate[4][4];
		Reg#(Bit#(8)) invtempmix <- mkRegU;
		Reg#(Bit#(8)) invtempfile <- mkRegU;
		Reg#(Bit#(8)) invtempfileOri <- mkRegU;
		Reg#(Bit#(8)) invtempfileSec <- mkRegU;
		Reg#(Bit#(8)) invtempfileFir <- mkRegU;
		Reg#(Bit#(8)) invtempfileThr <- mkRegU;
		Reg#(int) id <- mkReg(0);
		Reg#(int) ie <- mkReg(0);
		Reg#(int) ff <- mkReg(0);

		//---------------------------------- The interface --------------------------------------//
		Reg#(Bit#(8)) statetemp[4][4];
		Reg#(Bit#(8)) keymtemp[4][4];
		Reg#(Bit#(8)) resultttemp[4][4];
		Reg#(int) sigtemp <- mkReg(0);

		Reg#(int) i_int <- mkReg(0);
		Reg#(int) j_int <- mkReg(0);
		Reg#(int) sig <- mkReg(0);
		Reg#(int) cp <- mkReg(0);
		
		
///////////////////////////////////////////////////////////////////////////////////////////////////
//			Initialize matrix										     
///////////////////////////////////////////////////////////////////////////////////////////////////
		
		//---------------------------------- The interface --------------------------------------//
		for(Integer i = 0; i<4; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				statetemp[j][i] <- mkReg(0);

		for(Integer i = 0; i<4; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				keymtemp[j][i] <- mkReg(0);

		for(Integer i = 0; i<4; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				resultttemp[j][i] <- mkReg(0);	
		
		//------------------------------ Some essential matrix ----------------------------------//
		for(Integer i = 0; i<4; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				state[j][i] <- mkRegU;

		for(Integer i = 0; i<4; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				keym[j][i] <- mkRegU;

		for(Integer i = 0; i<4; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				resultt[j][i] <- mkRegU;

		for(Integer i = 0; i<16; i = i+1)
			for(Integer j = 0; j<16; j = j+1)
				sbox[j][i] <- mkRegU;
		
		for(Integer i = 0; i<44; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				keySched[j][i] <- mkRegU;

		for(Integer i = 0; i<10; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				mReword[j][i] <- mkRegU;

		//---------------------------------- Round key ---------------------------------------//
		for(Integer i = 0; i<4; i = i+1)
			tempShiftBits[i][0] <- mkRegU;

		for(Integer i = 0; i<10; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				rcon[j][i] <- mkRegU;

		for(Integer i = 0; i<4; i = i+1)
			tempSubOne[i][0] <- mkRegU;

		for(Integer i = 0; i<4; i = i+1)
			tempSubFour[i][0] <- mkRegU;

		for(Integer i = 0; i<4; i = i+1)
			test[i] <- mkReg(33);

		//-------------------------- AES encryption mixcolumn ------------------------------//
		for(Integer i = 0; i<4; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				tempstate[j][i] <- mkRegU;

		for(Integer i = 0; i<4; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				mix[j][i] <- mkRegU;
		
		//------------------------------- AES decipher ------------------------------------//
		for(Integer i = 0; i<16; i = i+1)
			for(Integer j = 0; j<16; j = j+1)
				invsbox[j][i] <- mkRegU;
	
		for(Integer i = 0; i<4; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				invmix[j][i] <- mkRegU;

		for(Integer i = 0; i<4; i = i+1)
			for(Integer j = 0; j<4; j = j+1)
				invtempstate[j][i] <- mkRegU;
		

/////////////////////////////////////////////////////////////////////////////////////////////
//			Prepare for AES					        			   
/////////////////////////////////////////////////////////////////////////////////////////////
		
		//-------------------------- Put data into register -------------------------------//
		rule init_state1_1 (step == 0);
			for(Integer i = 0; i<4; i = i+1)
				for(Integer j = 0; j<4; j = j+1)
					state[j][i] <= statetemp[j][i];

			for(Integer i = 0; i<4; i = i+1)
				for(Integer j = 0; j<4; j = j+1)
					keym[j][i] <= keymtemp[j][i];
			
			for(Integer i = 0; i<4; i = i+1)
				for(Integer j = 0; j<4; j = j+1)
					resultt[j][i] <= resultttemp[j][i];

			for(Integer i = 0; i<16; i = i+1)
				for(Integer j = 0; j<16; j = j+1)
					sbox[j][i] <= s_box[j][i];

			for(Integer i = 0; i<10; i = i+1)
				for(Integer j = 0; j<4; j = j+1)
					rcon[j][i] <= r_con[j][i];

			for(Integer i = 0; i<4; i = i+1)
				for(Integer j = 0; j<4; j = j+1)
					mix[j][i] <= m_ix[j][i];
			step <= 1;
		endrule

/////////////////////////////////////////////////////////////////////////////////////////////
//			Generate round key					        			   
/////////////////////////////////////////////////////////////////////////////////////////////
		
		//--------------- Initialize the first 4*4 round key using key -----------------//
		rule init_state1 (step == 1);
			for (Integer ia = 0; ia < 44; ia = ia+1)
				for (Integer ja = 0; ja < 4; ja = ja+1)begin
					if (ia < 4)begin
						keySched[ja][ia] <= keym[ja][ia];
					end
					else begin
						keySched[ja][ia] <= 8'h00;
					end
				end
			step <= 2;
		endrule

		//--------------------- Generate every first column in each group in rest of the round key -----------------------//
		// i_rk change from 0 - 9
		rule rest_sched (step == 2);
			for (Integer j = 0; j < 4; j = j+1)
				mReword[j][i_rk] <= keySched[j][(i_rk+1)*4-1];
			step <= 3;
		endrule
		
		rule rest_sched1 (step == 3);
			tempFirstBit <= keySched[0][(i_rk+1)*4-1];
			step <= 4;
		endrule
		
		// 1.0. Move each row's mReword parameters 1 bit left
		rule rest_sched2 (step == 4);
			for (Integer p = 1; p < 4; p = p+1)begin
				tempShiftBits[p-1][0] <= mReword[p][i_rk];
			end
			step <= 5;
		endrule

		// 1.2. Put the original first parameter of mReword at the end
		//this step can achieve each row shift left one bit
		rule rest_sched3 (step == 5);
			tempShiftBits[3][0] <= tempFirstBit;
			step <= 6;
		endrule

		
		// 2.0. Doing Subword
		// z_rk change from 0 - 3
		rule rest_sched4 (step == 6);
			mReword[z_rk][i_rk] <= tempShiftBits[z_rk][0];			
			step <= 200;
		endrule

		rule rest_sched4_0 (step == 200);
			tempSub <= mReword[z_rk][i_rk];
			step <= 7;
		endrule

		// 2.1. Fetch X & Y
		rule rest_sched4_1 (step == 7);
			tempSub1 <= tempSub[7:4];
			tempSub2 <= tempSub[3:0];
			step <= 8;
		endrule

		// 2.1. Doing Subword, check the value using X and Y
		rule rest_sched4_2 (step == 8);
			tempRcon <= sbox[tempSub1][tempSub2];
			step <= 9;
		endrule

		// 2.2. Do XOR with Rcon
		// 2.2. Do XOR with the same row but previous group
		rule rest_sched4_3 (step == 9);
			keySched[z_rk][(i_rk+1)*4] <= tempRcon ^ rcon[z_rk][i_rk] ^ keySched[z_rk][i_rk*4];
			step <= 10;
		endrule

		rule rest_sched5 (step == 10);
			if (z_rk < 3)begin
				z_rk <= z_rk+1;
				step <= 6;
			end
			else begin
				z_rk <= 0;
				step <= 11;
			end
		endrule
		
		//------------------ Generate the rest 3 column in each group --------------------//
		// k_rk change from 1 - 3
		// p_rk change from 0 - 3
		rule rest_sched6 (step == 11);
			//doing Subword, fetch X and Y
			tempSubOne[p_rk][0] <= keySched[p_rk][(4*i_rk)+k_rk+3];
			tempSubFour[p_rk][0] <= keySched[p_rk][(4*i_rk)+k_rk];
			step <= 12;
		endrule

		rule rest_sched7 (step == 12);
			keySched[p_rk][(4*i_rk)+4+k_rk] <= tempSubOne[p_rk][0] ^ tempSubFour[p_rk][0];
			step <= 13;
		endrule

		rule rest_sched8 (step == 13);
			if (p_rk < 3)begin
				p_rk <= p_rk +1;
				step <= 11;
			end
			else begin
				p_rk <= 0;
				if (k_rk < 3)begin
					k_rk <= k_rk + 1;
					step <= 11;
				end
				else begin
					k_rk <= 1;
					if (i_rk < 9)begin
						i_rk <= i_rk + 1;
						step <= 2;
					end
					else begin
						step <= 14; //test 14
					end
				end
			end

		endrule

/////////////////////////////////////////////////////////////////////////////////////////////
//			Decide to do Encryption/Decipher					 		   
/////////////////////////////////////////////////////////////////////////////////////////////
		rule fetch_signal (step == 14);
			sig <= sigtemp;
			step <= 400;
		endrule
		rule fetch_signal1 (step == 400);
			if (sig == 1)begin
				step <= 401;
			end
			else begin
				step <= 39;
			end
		endrule

/////////////////////////////////////////////////////////////////////////////////////////////
//			Start Encryption					        			   
/////////////////////////////////////////////////////////////////////////////////////////////
		
		//------------------ Initialize -> Add round key --------------------//
		rule add_round_key (step == 401);
			for (Integer im = 0; im < 4; im = im+1)
				for (Integer jm = 0; jm < 4; jm = jm+1)
					state[jm][im] <= keySched[jm][im] ^ state[jm][im];
			step <= 15;
		endrule

/////////////////////////////////////////////////////////////////////////////////////////////
//			Start Round Encryption					        			   
/////////////////////////////////////////////////////////////////////////////////////////////
		
		//------------------------- Step 1 -> ByteSubstitution ---------------------------//
		// a change from 0 - 9
		// 1. Fetch each element
		rule aes_byte_sub (step == 15);
			tSub <= state[c][b];
			step <= 16;
		endrule

		// 2. Fetch X & Y
		rule aes_byte_sub2 (step == 16);
			tSub1 <= tSub[7:4];
			tSub2 <= tSub[3:0];
			step <= 17;
		endrule

		// 3. Do substitution
		rule aes_byte_sub3 (step == 17);
			state[c][b] <= sbox[tSub1][tSub2];
			if (c < 3)begin
				c <= c+1;
				step <= 15;
			end
			else begin
				c <= 0;
				if (b < 3)begin
					b <= b+1;
					step <= 15;
				end
				else begin
					b <= 0;
					step <= 18; 
				end
			end
		endrule

		//------------------------- Step 2 -> ShiftRows ---------------------------//
		// 1. Second row shift
		rule aes_sr (step == 18);
			tempshift1 <= state[1][0];
			step <= 19;
		endrule

		rule aes_sr1 (step == 19);
			for (Integer i = 1; i < 4; i = i+1)
				state[1][i-1] <= state[1][i];
			step <= 20;
		endrule

		rule aes_sr2 (step == 20);
			state[1][3] <= tempshift1;
			step <= 21; 
		endrule
		
		// 2. Third row shift
		rule aes_sr3 (step == 21);
			tempshift2 <= state[2][0];
			tempshift3 <= state[2][1];
			step <= 22;
		endrule
		
		rule aes_sr4 (step == 22);
			for (Integer i = 2; i < 4; i = i+1)
				state[2][i-2] <= state[2][i];
			step <= 23;
		endrule

		rule aes_sr5 (step == 23);
			state[2][2] <= tempshift2;
			state[2][3] <= tempshift3;
			step <= 24;
		endrule

		// 3. Fourth row shift
		rule aes_sr6 (step == 24);
			tempshift4 <= state[3][3];
			tempshift5 <= state[3][0];
			tempshift6 <= state[3][1];
			tempshift7 <= state[3][2];
			step <= 25;
		endrule

		rule aes_sr7 (step == 25);
			state[3][0] <= tempshift4;
			state[3][1] <= tempshift5;
			state[3][2] <= tempshift6;
			state[3][3] <= tempshift7;
			step <= 26;
		endrule

		//--------------------------- Step 3 -> Mixcolumn -----------------------------//
		// 1. Judge the iteration time, if equal 9(10 time iteration) then jump this step
		rule mixcolumn (step == 26);
			if (a < 9)begin
				step <= 27;
			end
			else begin
				step <= 36;
			end
		endrule
		
		// 2. Fetch element from the intermediate matrix
		// id change from 0 - 3
		// ie change from 0 - 3
		// ff change from 0 - 3
		rule mixcolumn1 (step == 27);
			tempfile <= state[e][d];
			tempmix <= mix[f][e];
			step <= 28; //check
		endrule
		
		// 3. Do the Finite field arithmetic(also known as GF2^8)
		rule mixcolumn2 (step == 28);
			if (tempfile < 8'h80)begin						//p1
				if (tempmix == 8'h01)begin					//p2
					step <= 34; 
				end
				else begin									//p3
					if (tempmix == 8'h02)begin				//p4
						tempfile <= tempfile << 1;
						step <= 34;
					end
					else begin								//p5
						tempfile1 <= tempfile << 1;
						step <= 29;
					end
				end
			end
			else begin										//p6
				if (tempmix == 8'h01)begin					//p7
					step <= 34;
				end
				else begin									//p8
					if (tempmix == 8'h02)begin				//p9
						tempfile <= tempfile << 1;
						step <= 30;
					end
					else begin								//p10
						tempfile1 <= tempfile;
						step <= 31;
					end
				end
			end
		endrule

		rule mixcolumn_p5 (step == 29);
			tempfile <= tempfile ^ tempfile1;
			step <= 34;
		endrule

		rule mixcolumn_p9 (step == 30);
			tempfile <= tempfile ^ 8'h1b;
			step <= 34;
		endrule

		rule mixcolumn_p10 (step == 31);
			tempfile <= tempfile << 1;
			step <= 32;
		endrule

		rule mixcolumn_p10_1 (step == 32);
			tempfile <= tempfile ^ 8'h1b;
			step <= 33;
		endrule

		rule mixcolumn_p10_2 (step == 33);
			tempfile <= tempfile ^ tempfile1;
			step <= 34;
		endrule
		
		rule mixcolumn3 (step == 34);
			tempstate[f][e] <= tempfile;
			if (f < 3)begin
				f <= f+1;
				step <= 27; //27 check
			end
			else begin
				f <= 0;
				if (e < 3)begin
					e <= e+1;
					step <= 27; //27  above
				end
				else begin
					e <= 0;
					step <= 35;   //35   above
				end
			end
		endrule

		// 4. Do the matrix multiplication
		rule mixcolumn4 (step == 35);
			for (Integer i = 0; i<4; i = i+1)
				state[i][d] <= tempstate[i][0] ^ tempstate[i][1] ^tempstate[i][2] ^tempstate[i][3];
			if (d < 3)begin
				d <= d+1;
				step <= 27;
			end
			else begin
				d <= 0;
				step <= 36;
			end

		endrule

		//--------------------------- Step 4 -> Add round key -----------------------------//
		rule last_step (step == 36);
			state[h][g] <= keySched[h][4*a+4+g] ^ state[h][g];
			if (h < 3)begin
				h <= h+1;
				step <= 36;
			end
			else begin
				h <= 0;
				if (g < 3)begin
					g <= g+1;
					step <= 36;
				end
				else begin
					g <= 0;
					step <= 37;
				end
			end
		endrule

		rule last_step2 (step == 37);
			if (a < 9)begin
				a <= a+1;
				step <= 15;
			end
			else begin
			//================= !Check point: wait for interface output! ===================//
				cp <= 1;
			end
		endrule

/////////////////////////////////////////////////////////////////////////////////////////////
//			Start Decipher						       			   
/////////////////////////////////////////////////////////////////////////////////////////////		
		
		//-------------------------- Put data into register -------------------------------//
		rule init_decipher (step == 39);
			for(Integer i = 0; i<16; i = i+1)
				for(Integer j = 0; j<16; j = j+1)
					invsbox[j][i] <= inv_sbox[j][i];
	
			for(Integer i = 0; i<4; i = i+1)
				for(Integer j = 0; j<4; j = j+1)
					invmix[j][i] <= inv_mix[j][i];
			step <= 40;
		endrule

		//----------------------- Initialize -> Add round key ----------------------------//
		rule init_add_round_key (step == 40);
			for (Integer im = 0; im < 4; im = im+1)
				for (Integer jm = 0; jm < 4; jm = jm+1)
					resultt[jm][im] <= keySched[jm][im+40] ^ resultt[jm][im];
			step <= 41;	
		endrule
		
/////////////////////////////////////////////////////////////////////////////////////////////
//			Start Round Decipher					        			   
/////////////////////////////////////////////////////////////////////////////////////////////

		//----------------------- Step 1 -> Inverse shift rows ----------------------------//
		// k change from 0 - 9

		// 1. Second row shift
		rule inv_sr (step == 41);
			tshift1 <= resultt[1][3];	
			tshift2 <= resultt[1][0];
			tshift3 <= resultt[1][1];
			tshift4 <= resultt[1][2];
			step <= 42;
		endrule

		rule inv_sr1 (step == 42);
			resultt[1][0] <= tshift1;
			resultt[1][1] <= tshift2;
			resultt[1][2] <= tshift3;
			resultt[1][3] <= tshift4;
			step <= 43;
		endrule

		// 2. Third row shift
		rule inv_sr2 (step == 43);
			tshift11 <= resultt[2][2];	
			tshift22 <= resultt[2][3];
			tshift33 <= resultt[2][0];
			tshift44 <= resultt[2][1];
			step <= 44;
		endrule

		rule inv_sr3 (step == 44);
			resultt[2][0] <= tshift11;
			resultt[2][1] <= tshift22;
			resultt[2][2] <= tshift33;
			resultt[2][3] <= tshift44;
			step <= 45;
		endrule

		// 3. Fourth row shift
		rule inv_sr4 (step == 45);
			tshift5 <= resultt[3][1];	
			tshift6 <= resultt[3][2];
			tshift7 <= resultt[3][3];
			tshift8 <= resultt[3][0];
			step <= 46;
		endrule

		rule inv_sr5 (step == 46);
			resultt[3][0] <= tshift5;
			resultt[3][1] <= tshift6;
			resultt[3][2] <= tshift7;
			resultt[3][3] <= tshift8;
			step <= 47;
		endrule

		//----------------------- Step 2-> Inverse byte substitution ----------------------------//
		// bz change from 0-3
		// cz change from 0-3
		rule inv_sb (step == 47);
			tSb <= resultt[cz][bz];
			step <= 48;
		endrule

		rule inv_sb1 (step == 48);
			tSb1 <= tSb[7:4];
			tSb2 <= tSb[3:0];
			step <= 49;
		endrule

		rule inv_sb2 (step == 49);
			resultt[cz][bz] <= invsbox[tSb1][tSb2];
			if (cz < 3)begin
				cz <= cz+1;
				step <= 47;
			end
			else begin
				cz <= 0;
				if (bz < 3)begin
					bz <= bz+1;
					step <= 47;
				end
				else begin
					bz <= 0;
					step <= 50;
				end
			end
		endrule

		//----------------------- Step 3 -> Inverse add round key ----------------------------//
		// hz change from 0 - 3
		// gz change from 0 - 3
		rule inv_ark (step == 50);
			resultt[hz][gz] <= keySched[hz][gz+36-4*k] ^ resultt[hz][gz];
			if (hz < 3)begin
				hz <= hz+1;
				step <= 50;
			end
			else begin
				hz <= 0;
				if (gz < 3)begin
					gz <= gz+1;
					step <= 50;
				end
				else begin
					gz <= 0;
					step <= 51;
				end
			end
		endrule

		//----------------------- Step 4 -> Inverse mixcolumn ----------------------------//
		rule inv_mixcolumn (step == 51);
			invtempmix <= 8'h00;
			invtempfile <= 8'h00;
			invtempfileOri <= 8'h00; 			//Store Original Element
			invtempfileFir <= 8'h00;			//Store First iteration of Finite Field Arithmetic Result
			invtempfileSec <= 8'h00;			//Store Second Iteration Of Finite Field Arithmetic Result
			invtempfileThr <= 8'h00;			//Store Third Iteration Of Finite Field Arithmetic Result
			
			// Judge the Decipher iteration time, if equal to 9 then jump this step
			if (k < 9)begin
				step <= 52;
			end
			else begin
				step <= 81;
			end
		endrule
		
		// 1. Do the Finite Field Arithmetic
		// id change from 0 - 3
		// ie change from 0 - 3
		// ff change from 0 - 3
		rule inv_mixcolumn1 (step == 52);
			test[ie] <= id;
			invtempfile <= resultt[ie][id];
			invtempmix <= invmix[ff][ie];
			step <= 53;
		endrule

		rule inv_mixc (step == 53);
			invtempfileOri <= invtempfile;
			if (invtempfile < 8'h80)begin						//p1
				invtempfile <= invtempfile << 1;
				step <= 54;
			end
			else begin											//p8
				invtempfile <= invtempfile << 1;
				step <= 55;
			end
		endrule

		rule inv_p1 (step == 54);							// from p1
			invtempfileFir <= invtempfile;
			if (invtempfile < 8'h80)begin						//p2
				invtempfile <= invtempfile << 1;
				step <= 56;
			end
			else begin											//p5
				invtempfile <= invtempfile << 1;
				step <= 57;
			end
		endrule

		rule inv_p2 (step == 56);							// from p2
			invtempfileSec <= invtempfile;
			if (invtempfile < 8'h80)begin						//p3
				invtempfile <= invtempfile << 1;
				step <= 58;
			end
			else begin											//p4
				invtempfile <= invtempfile << 1;
				step <= 59;
			end
		endrule

		rule inv_p3 (step == 58);							// jump from p3
			invtempfileThr <= invtempfile;
			step <= 77;						// jump to judge
		endrule

		rule inv_p4 (step == 59);							// jump from p4
			invtempfile <= invtempfile ^ 8'h1b;
			step <= 60;
		endrule
		rule inv_p4_1 (step == 60);
			invtempfileThr <= invtempfile;
			step <=	77;						// jump to judge
		endrule

		rule inv_p5 (step == 57);							// jump from p5
			invtempfile <= invtempfile ^ 8'h1b;
			step <= 61;
		endrule
		rule inv_p5_1 (step == 61);
			invtempfileSec <= invtempfile;
			if (invtempfile < 8'h80)begin						//p6
				invtempfile <= invtempfile << 1;
				step <= 62;
			end
			else begin											//p7
				invtempfile <= invtempfile << 1;
				step <= 63;
			end
		endrule

		rule inv_p6 (step == 62);							// jump from p6
			invtempfileThr <= invtempfile;
			step <= 77;						// jump to judge
		endrule

		rule inv_p7 (step == 63);							// jump from p7
			invtempfile <= invtempfile ^ 8'h1b;
			step <= 64;
		endrule
		rule inv_p7_1 (step == 64);
			invtempfileThr <= invtempfile;
			step <= 77;						// jump to judge
		endrule

		rule inv_p8 (step == 55);							// jump from p8
			invtempfile <= invtempfile ^ 8'h1b;
			step <= 65;
		endrule
		rule inv_p8_1 (step == 65);
			invtempfileFir <= invtempfile;
			if (invtempfile < 8'h80)begin						// p9
				invtempfile <= invtempfile << 1;
				step <= 66;
			end
			else begin											// p12
				invtempfile <= invtempfile << 1;
				step <= 67;
			end
		endrule

		rule inv_p9 (step == 66);							// jump from p9
			invtempfileSec <= invtempfile;
			if (invtempfile < 8'h80)begin						// p10
				invtempfile <= invtempfile << 1;
				step <= 68;
			end
			else begin											// p11
				invtempfile <= invtempfile << 1;
				step <= 69;
			end
		endrule

		rule inv_10 (step == 68);							// jump from p10
			step <= 70;
		endrule
		rule inv_10_1 (step == 70);
			invtempfileThr <= invtempfile;
			step <= 77;						// jump to judge
		endrule

		rule inv_11 (step == 69);							// jump from p11
			step <= 71;
		endrule
		rule inv_11_1 (step == 71);
			invtempfile <= invtempfile ^ 8'h1b;
			step <= 72;
		endrule
		rule inv_11_2 (step == 72);
			invtempfileThr <= invtempfile;
			step <= 77;						// jump to judge
		endrule

		rule inv_12 (step == 67);							// jump from p12
			invtempfile <= invtempfile ^ 8'h1b;
			step <= 73;
		endrule
		rule inv_12_1 (step == 73);
			invtempfileSec <= invtempfile;
			if (invtempfile < 8'h80)begin						//p13
				invtempfile <= invtempfile << 1;
				step <= 74;
			end
			else begin											//p14
				invtempfile <= invtempfile << 1;
				step <= 75;
			end
		endrule

		rule inv_p13 (step == 74);							// jump from p13
			invtempfileThr <= invtempfile;
			step <=	77;						// jump to judge
		endrule

		rule inv_p14 (step == 75);							// jump from p14
			invtempfile <= invtempfile ^ 8'h1b;
			step <= 76;
		endrule
		rule inv_p14_1 (step == 76);
			invtempfileThr <= invtempfile;
			step <= 77;						// jump to judge
		endrule

		// 1.1 Complete the Finite Field Arithmetic
		rule judge (step == 77);
			if (invtempmix == 8'h09)begin	//Judge 0x09
				invtempfile <= invtempfileThr ^ invtempfileOri;
			end
			if (invtempmix == 8'h0b)begin
				invtempfile <= invtempfileThr ^ invtempfileFir ^ invtempfileOri;
			end
			if (invtempmix == 8'h0d)begin
				invtempfile <= invtempfileThr ^ invtempfileSec ^ invtempfileOri;
			end
			if (invtempmix == 8'h0e)begin
				invtempfile <= invtempfileThr ^ invtempfileSec ^ invtempfileFir;
			end
			step <= 78;
		endrule

		rule judge1 (step == 78);
			invtempstate[ff][ie] <= invtempfile;
			step <= 79;
		endrule

		rule judge2 (step == 79);
			 if (ff < 3)begin
				 ff <= ff+1;
				 step <= 52;
			 end
			 else begin
				 ff <= 0;
				 if (ie < 3)begin
					 ie <= ie+1;
					 step <= 52;
				 end
				 else begin
					 ie <= 0;
					 if (id < 4)begin
						 step <= 80;
					 end
					 else begin
						 id <= 0;
						 step <= 81;
					 end
				 end
			 end
		endrule

		// 2. Do the matrix multiplication
		rule judge3 (step == 80);
			for (Integer i4 = 0; i4 < 4; i4 = i4+1)begin
				resultt[i4][id] <= invtempstate[i4][0] ^ invtempstate[i4][1] ^ invtempstate[i4][2] ^ invtempstate[i4][3];
			end
			id <= id+1;
			step <= 52;
		endrule

		rule loop_end (step == 81);
			if (k < 9)begin
				k <= k+1;
				step <= 41;
			end
			else begin
			//================= !Check point: wait for interface output! ===================//
				cp <= 1;
			end
		endrule


/////////////////////////////////////////////////////////////////////////////////////////////
//			Interface Method					        			   
/////////////////////////////////////////////////////////////////////////////////////////////
		
		//----------------------- Method for loading input ----------------------------//
		// Transfer 32bit per clock cycle
		method Action loadInput(Bit#(32) dIn, int addr);
			//statetemp[0][0] <= dIn;
			temp <= dIn;
			
			if(addr == 0)begin
				statetemp[0][0] <= dIn[31:24];
				statetemp[1][0] <= dIn[23:16];
				statetemp[2][0] <= dIn[15:8];
				statetemp[3][0] <= dIn[7:0];
			end
			if(addr == 1)begin
				statetemp[0][1] <= dIn[31:24];
				statetemp[1][1] <= dIn[23:16];
				statetemp[2][1] <= dIn[15:8];
				statetemp[3][1] <= dIn[7:0];
			end
			if(addr == 2)begin
				statetemp[0][2] <= dIn[31:24];
				statetemp[1][2] <= dIn[23:16];
				statetemp[2][2] <= dIn[15:8];
				statetemp[3][2] <= dIn[7:0];
			end
			if(addr == 3)begin
				statetemp[0][3] <= dIn[31:24];
				statetemp[1][3] <= dIn[23:16];
				statetemp[2][3] <= dIn[15:8];
				statetemp[3][3] <= dIn[7:0];
			end
		endmethod

		//----------------------- Method for import cipher key ----------------------------//
		method Action importKey(Bit#(32) imKey, int addr);
			if(addr == 0)begin
				keymtemp[0][0] <= imKey[31:24];
				keymtemp[1][0] <= imKey[23:16];
				keymtemp[2][0] <= imKey[15:8];
				keymtemp[3][0] <= imKey[7:0];
			end
			if(addr == 1)begin
				keymtemp[0][1] <= imKey[31:24];
				keymtemp[1][1] <= imKey[23:16];
				keymtemp[2][1] <= imKey[15:8];
				keymtemp[3][1] <= imKey[7:0];
			end
			if(addr == 2)begin
				keymtemp[0][2] <= imKey[31:24];
				keymtemp[1][2] <= imKey[23:16];
				keymtemp[2][2] <= imKey[15:8];
				keymtemp[3][2] <= imKey[7:0];
			end
			if(addr == 3)begin
				keymtemp[0][3] <= imKey[31:24];
				keymtemp[1][3] <= imKey[23:16];
				keymtemp[2][3] <= imKey[15:8];
				keymtemp[3][3] <= imKey[7:0];
			end
		endmethod

		//----------------------- Method for load Encrypted text ----------------------------//
		method Action loadDestate(Bit#(32) des, int addr);
			if(addr == 0)begin
				resultttemp[0][0] <= des[31:24];
				resultttemp[1][0] <= des[23:16];
				resultttemp[2][0] <= des[15:8];
				resultttemp[3][0] <= des[7:0];
			end
			if(addr == 1)begin
				resultttemp[0][1] <= des[31:24];
				resultttemp[1][1] <= des[23:16];
				resultttemp[2][1] <= des[15:8];
				resultttemp[3][1] <= des[7:0];
			end
			if(addr == 2)begin
				resultttemp[0][2] <= des[31:24];
				resultttemp[1][2] <= des[23:16];
				resultttemp[2][2] <= des[15:8];
				resultttemp[3][2] <= des[7:0];
			end
			if(addr == 3)begin
				resultttemp[0][3] <= des[31:24];
				resultttemp[1][3] <= des[23:16];
				resultttemp[2][3] <= des[15:8];
				resultttemp[3][3] <= des[7:0];
			end
		endmethod  

		//------------------- Import the Encryption/Decipher signal ------------------------//
		method Action check_signal(int signal) if (step == 700);
			sigtemp <= signal;
			step <= 0; //debug change 0 ori
		endmethod

		//------------------ Output Encryption/Decipher DONE signal -----------------------//
		method int checkpoint ();
			return cp;
		endmethod
		method int output_signal();
			return sig;
		endmethod

		//----------------------- Output the Encryption result ----------------------------//
		method Bit#(8) output_state (int i, int j);
			Bit#(8) out_k;
			out_k = state[i][j];
			return out_k;
		endmethod

		//------------------------ Output the Decipher result ----------------------------//
		method Bit#(8) output_result (int i, int j);
			Bit#(8) out_r;
			out_r = resultt[i][j];
			return out_r;
		endmethod


	endmodule: mkTb

endpackage: AESchange
