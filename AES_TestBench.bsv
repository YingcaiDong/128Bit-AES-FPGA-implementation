package AEStb;
	import AESchange::*;
	(*synthesize*)
	module tb_ip_text (Empty);
		Ifc_main_type dataInput <- mkTb;

		Reg#(int) flag <- mkReg(0);
		Reg#(Bit#(8)) the_output[4][4];
		Reg#(int) ii <- mkReg(0);
		Reg#(int) jj <- mkReg(0);

		for (Integer i=0;i<4;i=i+1)
			for(Integer j=0;j<4;j=j+1)
				the_output[j][i] <- mkRegU;
		
		//----------------------- Input plain text ----------------------------//
		rule input_data (flag == 0);
			dataInput.loadInput('h3243f6a8, 0);
			flag <= 1;
		endrule
		rule input_data1 (flag == 1);
			dataInput.loadInput('h885a308d, 1);
			flag <= 2;
		endrule
		rule input_data2 (flag == 2);
			dataInput.loadInput('h313198a2, 2);
			flag <= 3;
		endrule
		rule input_data3 (flag == 3);
			dataInput.loadInput('he0370734, 3);
			flag <= 4;
		endrule
		
		//----------------------- Input cipher key ----------------------------//
		rule input_key (flag == 4);
			dataInput.importKey(32'h2b7e1516, 0);
			flag <= 5;
		endrule
		rule input_key1 (flag == 5);
			dataInput.importKey(32'h28aed2a6, 1);
			flag <= 6;
		endrule
		rule input_key2 (flag == 6);
			dataInput.importKey(32'habf71588, 2);
			flag <= 7;
		endrule
		rule input_key3 (flag == 7);
			dataInput.importKey(32'h09cf4f3c, 3);
			flag <= 8;
		endrule

		//--------------------- Input encrypted text --------------------------//
		rule input_destate (flag == 8);
			dataInput.loadDestate(32'h3925841d, 0);
			flag <= 9;
		endrule
		rule input_destate1 (flag == 9);
			dataInput.loadDestate(32'h02dc09fb, 1);
			flag <= 10;
		endrule
		rule input_destate2 (flag == 10);
			dataInput.loadDestate(32'hdc118597, 2);
			flag <= 11;
		endrule
		rule input_destate3 (flag == 11);
			dataInput.loadDestate(32'h196a0b32, 3);
			flag <= 12;
		endrule

		//-------------- Set the Encryption/Decipher signal -------------------//
		rule sendsignal (flag == 12);
			//1 means enc
			//0 means deci
			dataInput.check_signal(0);
			flag <= 400;
		endrule

		//---------------- Get the result from the Module --------------------//
		rule getoutput (flag == 400);
			if (dataInput.checkpoint == 0)begin
				flag <= 400;
			end
			else begin
				if (dataInput.output_signal == 1)begin
					flag <= 13;
				end
				else begin
					flag <= 14;
				end
			end
		endrule

		rule getoutput1 (flag == 13);
			the_output[jj][ii] <= dataInput.output_state(jj, ii);
			if (jj <3)begin
				jj <= jj+1;
				flag <= 13;
			end
			else begin
				jj <= 0;
				if (ii <3)begin
					ii <= ii+1;
					flag <= 13;
				end
				else begin
					ii <= 0;
					flag <= 15;
				end
			end
		endrule

		rule getoutput2 (flag == 14);
			the_output[jj][ii] <= dataInput.output_result(jj,ii);
			if (jj <3)begin
				jj <= jj+1;
				flag <= 14;
			end
			else begin
				jj <= 0;
				if (ii <3)begin
					ii <= ii+1;
					flag <= 14;
				end
				else begin
					ii <= 0;
					flag <= 15;
				end
			end
		endrule
		
		//--------------------- Display the result --------------------------//
		rule displayresult (flag == 15);
			for(Integer i = 0; i<4; i = i+1)
				for(Integer j = 0; j<4; j = j+1)
					$display ("result = %h", the_output[j][i]);
					$finish (0);
			$finish (0);
		endrule

	endmodule: tb_ip_text

endpackage: AEStb
