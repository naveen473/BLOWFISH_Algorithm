`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 15.10.2022 10:38:38
// Design Name: 
// Module Name: decrypt
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module decrypt(
    input clk,
    input rst,
    input [63:0] din,
    output reg [63:0] dout
    );
    reg [31:0]P[17:0];
    reg [31:0]Pk[17:0];
    reg [31:0]key[13:0];
    reg [31:0] left[17:0],right[17:0];
    reg [31:0] out1,out2,out3,out4;
    reg [31:0] o1,o2,o3;
    reg [31:0]sbox1[255:0];
    reg [31:0]sbox2[255:0];
    reg [31:0]sbox3[255:0];
    reg [31:0]sbox4[255:0];
    integer i,j;
    reg [7:0]s1,s2,s3,s4;
    
 
    initial   // Initialising the  P-array,Key,S-box
    begin
    // P-array
    P[0]=32'h243F6A88;
    P[1]=32'h85A308D3;
    P[2]=32'h13198A2E;
    P[3]=32'h03707344;  
    P[4]=32'hA4093822;
    P[5]=32'h299F31D0;
    P[6]=32'h082EFA98;
    P[7]=32'hEC4E6C89;
    P[8]=32'h452821E6;
    P[9]=32'h38D01377;
    P[10]=32'hBE5466CF;
    P[11]=32'h34E90C6C;
    P[12]=32'hC0AC29B7;
    P[13]=32'hC97C50DD;
    P[14]=32'h3F84D5B5;
    P[15]=32'hB5470917;
    P[16]=32'h9216D5D9;
    P[17]=32'h8979FB1B;
    
    // Key
    key[0]=32'h4B7A70E9;
    key[1]=32'hB5B32944;
    key[2]=32'hDB75092E;
    key[3]=32'hC4192623;
    key[4]=32'hAD6EA6B0;
    key[5]=32'h49A7DF7D;
    key[6]=32'h9CEE60B8;
    key[7]=32'h8FEDB266;
    key[8]=32'hECAA8C71;
    key[9]=32'h699A17FF;
    key[10]=32'h5664526C;
    key[11]=32'hC2B19EE1;
    key[12]=32'h193602A5;
    key[13]=32'h75094C29; 
    
    //Sbox
            sbox1[8'h00] = 32'hD1310BA6;
            sbox1[8'h01] = 32'h98BFB5AC;
            sbox1[8'h02] = 32'h2FFD72DF;
            sbox1[8'h03] = 32'hD01ADFB7;
            sbox1[8'h04] = 32'hB8E1AFED;
            sbox1[8'h05] = 32'h6A267E96;
            sbox1[8'h06] = 32'hBA7C9045;
            sbox1[8'h07] = 32'hF12C7F99;
            sbox1[8'h08] = 32'h24A19947;
            sbox1[8'h09] = 32'hB3916CF7;
            sbox1[8'h0a] = 32'h0801F2E2;
            sbox1[8'h0b] = 32'h858EFC16;
            sbox1[8'h0c] = 32'h636920D8;
            sbox1[8'h0d] = 32'h71574E69;
            sbox1[8'h0e] = 32'hA458FEA3;
            sbox1[8'h0f] = 32'hF4933D7E;
            sbox1[8'h10] = 32'h0D95748F;
            sbox1[8'h11] = 32'h728EB658;
            sbox1[8'h12] = 32'h718BCD58;
            sbox1[8'h13] = 32'h82154AEE;
            sbox1[8'h14] = 32'h7B54A41D;
            sbox1[8'h15] = 32'hC25A59B5;
            sbox1[8'h16] = 32'h9C30D539;
            sbox1[8'h17] = 32'h2AF26013;
            sbox1[8'h18] = 32'hC5D1B023;
            sbox1[8'h19] = 32'h286085F0;
            sbox1[8'h1a] = 32'hCA417918;
            sbox1[8'h1b] = 32'hB8DB38EF;
            sbox1[8'h1c] = 32'h8E79DCB0;
            sbox1[8'h1d]=32'h603A180E;
            sbox1[8'h1e]=32'h6C9E0E8B;
            sbox1[8'h1f]=32'hB01E8A3E;
            
            sbox1[8'h20]=32'hD71577C1;
            sbox1[8'h21]=32'hBD314B27;
            sbox1[8'h22]=32'h78AF2FDA;
            sbox1[8'h23]=32'h55605C60;
            sbox1[8'h24]=32'hE65525F3;
            sbox1[8'h25]=32'hAA55AB94;
            sbox1[8'h26]=32'h57489862;
            sbox1[8'h27]=32'h63E81440;
            sbox1[8'h28]=32'h55CA396A;
            sbox1[8'h29]=32'h2AAB10B6;
            sbox1[8'h2a]=32'hB4CC5C34;
            sbox1[8'h2b]=32'h1141E8CE;
            sbox1[8'h2c]=32'hA15486AF;
            sbox1[8'h2d]=32'h7C72E993;
            sbox1[8'h2e]=32'hB3EE1411;
            sbox1[8'h2f]=32'h636FBC2A;
            
            sbox1[8'h30]=32'h2BA9C55D;
            sbox1[8'h31]=32'h741831F6;
            sbox1[8'h32]=32'hCE5C3E16;
            sbox1[8'h33]=32'h9B87931E;
            sbox1[8'h34]=32'hAFD6BA33;
            sbox1[8'h35]=32'h6C24CF5C;
            sbox1[8'h36]=32'h7A325381;
            sbox1[8'h37]=32'h28958677;
            sbox1[8'h38]=32'h3B8F4898;
            sbox1[8'h39]=32'h6B4BB9AF;
            sbox1[8'h3a]=32'hC4BFE81B;
            sbox1[8'h3b]=32'h66282193;
            sbox1[8'h3c]=32'h61D809CC;
            sbox1[8'h3d]=32'hFB21A991;
            sbox1[8'h3e]=32'h487CAC60;
            sbox1[8'h3f]=32'h5DEC8032;
            
            sbox1[8'h40]=32'hEF845D5D;
            sbox1[8'h41]=32'hE98575B1;
            sbox1[8'h42]=32'hDC262302;
            sbox1[8'h43]=32'hEB651B88;
            sbox1[8'h44]=32'h23893E81;
            sbox1[8'h45]=32'hD396ACC5;
            sbox1[8'h46]=32'h0F6D6FF3;
            sbox1[8'h47]=32'h83F44239;
            sbox1[8'h48]=32'h2E0B4482;
            sbox1[8'h49]=32'hA4842004;
            sbox1[8'h4a]=32'h69C8F04A;
            sbox1[8'h4b]=32'h9E1F9B5E;
            sbox1[8'h4c]=32'h21C66842;
            sbox1[8'h4d]=32'hF6E96C9A;
            sbox1[8'h4e]=32'h670C9C61;
            sbox1[8'h4f]=32'hABD388F0;
            
            sbox1[8'h50]=32'h6A51A0D2;
            sbox1[8'h51]=32'hD8542F68;
            sbox1[8'h52]=32'h960FA728;
            sbox1[8'h53]=32'hAB5133A3;
            sbox1[8'h54]=32'h6EEF0B6C;
            sbox1[8'h55]=32'h137A3BE4;
            sbox1[8'h56]=32'hBA3BF050;
            sbox1[8'h57]=32'h7EFB2A98;
            sbox1[8'h58]=32'hA1F1651D;
            sbox1[8'h59]=32'h39AF0176;
            sbox1[8'h5a]=32'h66CA593E;
            sbox1[8'h5b]=32'h82430E88;
            sbox1[8'h5c]=32'h8CEE8619;
            sbox1[8'h5d]=32'h456F9FB4;
            sbox1[8'h5e]=32'h7D84A5C3;
            sbox1[8'h5f]=32'h3B8B5EBE;
            
            sbox1[8'h60]=32'hE06F75D8;
            sbox1[8'h61]=32'h85C12073;
            sbox1[8'h62]=32'h401A449F;
            sbox1[8'h63]=32'h56C16AA6;
            sbox1[8'h64]=32'h4ED3AA62;
            sbox1[8'h65]=32'h363F7706;
            sbox1[8'h66]=32'h1BFEDF72;
            sbox1[8'h67]=32'h429B023D;
            sbox1[8'h68]=32'h37D0D724;
            sbox1[8'h69]=32'hD00A1248;
            sbox1[8'h6a]=32'hDB0FEAD3;
            sbox1[8'h6b]=32'h49F1C09B;
            sbox1[8'h6c]=32'h075372C9;
            sbox1[8'h6d]=32'h80991B7B;
            sbox1[8'h6e]=32'h25D479D8;
            sbox1[8'h6f]=32'hF6E8DEF7;
            
            sbox1[8'h70]=32'hE3FE501A;
            sbox1[8'h71]=32'hB6794C3B;
            sbox1[8'h72]=32'h976CE0BD;
            sbox1[8'h73]=32'h04C006BA;
            sbox1[8'h74]=32'hC1A94FB6;
            sbox1[8'h75]=32'h409F60C4;
            sbox1[8'h76]=32'h5E5C9EC2;
            sbox1[8'h77]=32'h196A2463;
            sbox1[8'h78]=32'h68FB6FAF;
            sbox1[8'h79]=32'h3E6C53B5;
            sbox1[8'h7a]=32'h1339B2EB;
            sbox1[8'h7b]=32'h3B52EC6F;
            sbox1[8'h7c]=32'h6DFC511F;
            sbox1[8'h7d]=32'h9B30952C;
            sbox1[8'h7e]=32'hCC814544;
            sbox1[8'h7f]=32'hAF5EBD09;
            
            sbox1[8'h80]=32'hBEE3D004;
            sbox1[8'h81]=32'hDE334AFD;
            sbox1[8'h82]=32'h660F2807;
            sbox1[8'h83]=32'h192E4BB3;
            sbox1[8'h84]=32'hC0CBA857;
            sbox1[8'h85]=32'h45C8740F;
            sbox1[8'h86]=32'hD20B5F39;
            sbox1[8'h87]=32'hB9D3FBDB;
            sbox1[8'h88]=32'h5579C0BD;
            sbox1[8'h89]=32'h1A60320A;
            sbox1[8'h8a]=32'hD6A100C6;
            sbox1[8'h8b]=32'h402C7279;
            sbox1[8'h8c]=32'h679F25FE;
            sbox1[8'h8d]=32'hFB1FA3CC;
            sbox1[8'h8e]=32'h8EA5E9F8;
            sbox1[8'h8f]=32'hDB3222F8;
            
            sbox1[8'h90]=32'h3C7516DF;
            sbox1[8'h91]=32'hFD616B15;
            sbox1[8'h92]=32'h2F501EC8;
            sbox1[8'h93]=32'hAD0552AB;
            sbox1[8'h94]=32'h323DB5FA;
            sbox1[8'h95]=32'hFD238760;
            sbox1[8'h96]=32'h53317B48;
            sbox1[8'h97]=32'h3E00DF82;
            sbox1[8'h98]=32'h9E5C57BB;
            sbox1[8'h99]=32'hCA6F8CA0;
            sbox1[8'h9a]=32'h1A87562E;
            sbox1[8'h9b]=32'hDF1769DB;
            sbox1[8'h9c]=32'hD542A8F6;
            sbox1[8'h9d]=32'h287EFFC3;
            sbox1[8'h9e]=32'hAC6732C6;
            sbox1[8'h9f]=32'h8C4F5573;
            
            sbox1[8'ha0]=32'h695B27B0;
            sbox1[8'ha1]=32'hBBCA58C8;
            sbox1[8'ha2]=32'hE1FFA35D;
            sbox1[8'ha3]=32'hB8F011A0;
            sbox1[8'ha4]=32'h10FA3D98;
            sbox1[8'ha5]=32'hFD2183B8;
            sbox1[8'ha6]=32'h4AFCB56C;
            sbox1[8'ha7]=32'h2DD1D35B;
            sbox1[8'ha8]=32'h9A53E479;
            sbox1[8'ha9]=32'hB6F84565;
            sbox1[8'haa]=32'hD28E49BC;
            sbox1[8'hab]=32'h4BFB9790;
            sbox1[8'hac]=32'hE1DDF2DA;
            sbox1[8'had]=32'hA4CB7E33;
            sbox1[8'hae]=32'h62FB1341;
            sbox1[8'haf]=32'hCEE4C6E8;
            
            sbox1[8'hb0]=32'hEF20CADA;
            sbox1[8'hb1]=32'h36774C01;
            sbox1[8'hb2]=32'hD07E9EFE;
            sbox1[8'hb3]=32'h2BF11FB4;
            sbox1[8'hb4]=32'h95DBDA4D;
            sbox1[8'hb5]=32'hAE909198;
            sbox1[8'hb6]=32'hEAAD8E71;
            sbox1[8'hb7]=32'h6B93D5A0;
            sbox1[8'hb8]=32'hD08ED1D0;
            sbox1[8'hb9]=32'hAFC725E0;
            sbox1[8'hba]=32'h8E3C5B2F;
            sbox1[8'hbb]=32'h8E7594B7;
            sbox1[8'hbc]=32'h8FF6E2FB;
            sbox1[8'hbd]=32'hF2122B64;
            sbox1[8'hbe]=32'h8888B812;
            sbox1[8'hbf]=32'h900DF01C;
            
            sbox1[8'hc0]=32'h4FAD5EA0;
            sbox1[8'hc1]=32'h688FC31C;
            sbox1[8'hc2]=32'hD1CFF191;
            sbox1[8'hc3]=32'hB3A8C1AD;
            sbox1[8'hc4]=32'h2F2F2218;
            sbox1[8'hc5]=32'hBE0E1777;
            sbox1[8'hc6]=32'hEA752DFE;
            sbox1[8'hc7]=32'h8B021FA1;
            sbox1[8'hc8]=32'hE5A0CC0F;
            sbox1[8'hc9]=32'hB56F74E8;
            sbox1[8'hca]=32'h18ACF3D6;
            sbox1[8'hcb]=32'hCE89E299;
            sbox1[8'hcc]=32'hB4A84FE0;
            sbox1[8'hcd]=32'hFD13E0B7;
            sbox1[8'hce]=32'h7CC43B81;
            sbox1[8'hcf]=32'hD2ADA8D9;
            
            sbox1[8'hd0]=32'h165FA266;
            sbox1[8'hd1]=32'h80957705;
            sbox1[8'hd2]=32'h93CC7314;
            sbox1[8'hd3]=32'h211A1477;
            sbox1[8'hd4]=32'hE6AD2065;
            sbox1[8'hd5]=32'h77B5FA86;
            sbox1[8'hd6]=32'hC75442F5;
            sbox1[8'hd7]=32'hFB9D35CF;
            sbox1[8'hd8]=32'hEBCDAF0C;
            sbox1[8'hd9]=32'h7B3E89A0;
            sbox1[8'hda]=32'hD6411BD3;
            sbox1[8'hdb]=32'hAE1E7E49;
            sbox1[8'hdc]=32'h00250E2D;
            sbox1[8'hdd]=32'h2071B35E;
            sbox1[8'hde]=32'h226800BB;
            sbox1[8'hdf]=32'h57B8E0AF;
            
            sbox1[8'he0]=32'h2464369B;
            sbox1[8'he1]=32'hF009B91E;
            sbox1[8'he2]=32'h5563911D;
            sbox1[8'he3]=32'h59DFA6AA;
            sbox1[8'he4]=32'h78C14389;
            sbox1[8'he5]=32'hD95A537F;
            sbox1[8'he6]=32'h207D5BA2;
            sbox1[8'he7]=32'h02E5B9C5;
            sbox1[8'he8]=32'h83260376;
            sbox1[8'he9]=32'h6295CFA9;
            sbox1[8'hea]=32'h11C81968;
            sbox1[8'heb]=32'h4E734A41;
            sbox1[8'hec]=32'hB3472DCA;
            sbox1[8'hed]=32'h7B14A94A;
            sbox1[8'hee]=32'h1B510052;
            sbox1[8'hef]=32'h9A532915;
            
            sbox1[8'hf0]=32'hD60F573F;
            sbox1[8'hf1]=32'hBC9BC6E4;
            sbox1[8'hf2]=32'h2B60A476;
            sbox1[8'hf3]=32'h81E67400;
            sbox1[8'hf4]=32'h08BA6FB5;
            sbox1[8'hf5]=32'h571BE91F;
            sbox1[8'hf6]=32'hF296EC6B;
            sbox1[8'hf7]=32'h2A0DD915;
            sbox1[8'hf8]=32'hB6636521;
            sbox1[8'hf9]=32'hE7B9F9B6;
            sbox1[8'hfa]=32'hFF34052E;
            sbox1[8'hfb]=32'hC5855664;
            sbox1[8'hfc]=32'h53B02D5D;
            sbox1[8'hfd]=32'hA99F8FA1;
            sbox1[8'hfe]=32'h08BA4799;
            sbox1[8'hff]=32'h6E85076A;
    
        //Sbox-2
                
        sbox2[8'h00]=32'h4B7A70E9;
        sbox2[8'h01]=32'hB5B32944;
        sbox2[8'h02]=32'hDB75092E;
        sbox2[8'h03]=32'hC4192623;
        sbox2[8'h04]=32'hAD6EA6B0;
        sbox2[8'h05]=32'h49A7DF7D;
        sbox2[8'h06]=32'h9CEE60B8;
        sbox2[8'h07]=32'h8FEDB266;
        sbox2[8'h08]=32'hECAA8C71;
        sbox2[8'h09]=32'h699A17FF;
        sbox2[8'h0a]=32'h5664526C;
        sbox2[8'h0b]=32'hC2B19EE1;
        sbox2[8'h0c]=32'h193602A5;
        sbox2[8'h0d]=32'h75094C29;
        sbox2[8'h0e]=32'hA0591340;
        sbox2[8'h0f]=32'hE4183A3E;
        
        sbox2[8'h10]=32'h3F54989A;
        sbox2[8'h11]=32'h5B429D65;
        sbox2[8'h12]=32'h6B8FE4D6;
        sbox2[8'h13]=32'h99F73FD6;
        sbox2[8'h14]=32'hA1D29C07;
        sbox2[8'h15]=32'hEFE830F5;
        sbox2[8'h16]=32'h4D2D38E6;
        sbox2[8'h17]=32'hF0255DC1;
        sbox2[8'h18]=32'h4CDD2086;
        sbox2[8'h19]=32'h8470EB26;
        sbox2[8'h1a]=32'h6382E9C6;
        sbox2[8'h1b]=32'h021ECC5E;
        sbox2[8'h1c]=32'h09686B3F;
        sbox2[8'h1d]=32'h3EBAEFC9;
        sbox2[8'h1e]=32'h3C971814;
        sbox2[8'h1f]=32'h6B6A70A1;
        
        sbox2[8'h20]=32'h687F3584;
        sbox2[8'h21]=32'h52A0E286;
        sbox2[8'h22]=32'hB79C5305;
        sbox2[8'h23]=32'hAA500737;
        sbox2[8'h24]=32'h3E07841C;
        sbox2[8'h25]=32'h7FDEAE5C;
        sbox2[8'h26]=32'h8E7D44EC;
        sbox2[8'h27]=32'h5716F2B8;
        sbox2[8'h28]=32'hB03ADA37;
        sbox2[8'h29]=32'hF0500C0D;
        sbox2[8'h2a]=32'hF01C1F04;
        sbox2[8'h2b]=32'h0200B3FF;
        sbox2[8'h2c]=32'hAE0CF51A;
        sbox2[8'h2d]=32'h3CB574B2;
        sbox2[8'h2e]=32'h25837A58;
        sbox2[8'h2f]=32'hDC0921BD;
        
        sbox2[8'h30]=32'hD19113F9;
        sbox2[8'h31]=32'h7CA92FF6;
        sbox2[8'h32]=32'h94324773;
        sbox2[8'h33]=32'h22F54701;
        sbox2[8'h34]=32'h3AE5E581;
        sbox2[8'h35]=32'h37C2DADC;
        sbox2[8'h36]=32'hC8B57634;
        sbox2[8'h37]=32'h9AF3DDA7;
        sbox2[8'h38]=32'hA9446146;
        sbox2[8'h39]=32'h0FD0030E;
        sbox2[8'h3a]=32'hECC8C73E;
        sbox2[8'h3b]=32'hA4751E41;
        sbox2[8'h3c]=32'hE238CD99;
        sbox2[8'h3e]=32'h3BEA0E2F;
        sbox2[8'h3d]=32'h3280BBA1;
        sbox2[8'h3f]=32'h183EB331;
        
        sbox2[8'h40]=32'h4E548B38;
        sbox2[8'h41]=32'h4F6DB908;
        sbox2[8'h42]=32'h6F420D03;
        sbox2[8'h43]=32'hF60A04BF;
        sbox2[8'h44]=32'h2CB81290;
        sbox2[8'h45]=32'h24977C79;
        sbox2[8'h46]=32'h5679B072;
        sbox2[8'h47]=32'hBCAF89AF;
        sbox2[8'h48]=32'hDE9A771F;
        sbox2[8'h49]=32'hD9930810;
        sbox2[8'h4a]=32'hB38BAE12;
        sbox2[8'h4b]=32'hDCCF3F2;
        sbox2[8'h4c]=32'h5512721F;
        sbox2[8'h4d]=32'h2E6B7124;
        sbox2[8'h4e]=32'h501ADDE6;
        sbox2[8'h4f]=32'h9F84CD87;
        
        sbox2[8'h50]=32'h7A584718;
        sbox2[8'h51]=32'h7408DA17;
        sbox2[8'h52]=32'hBC9F9ABC;
        sbox2[8'h53]=32'hE94B7D8C;
        sbox2[8'h54]=32'hEC7AEC3A;
        sbox2[8'h55]=32'hDB851DFA;
        sbox2[8'h56]=32'h63094366;
        sbox2[8'h57]=32'hC464C3D2;
        sbox2[8'h58]=32'hEF1C1847;
        sbox2[8'h59]=32'h3215D908;
        sbox2[8'h5a]=32'hDD433B37;
        sbox2[8'h5b]=32'h24C2BA16;
        sbox2[8'h5c]=32'h12A14D43;
        sbox2[8'h5d]=32'h2A65C451;
        sbox2[8'h5e]=32'h50940002;
        sbox2[8'h5f]=32'h133AE4DD;
        
        sbox2[8'h60]=32'h71DFF89E;
        sbox2[8'h61]=32'h10314E55;
        sbox2[8'h62]=32'h81AC77D6;
        sbox2[8'h63]=32'h5F11199B;
        sbox2[8'h64]=32'h043556F1;
        sbox2[8'h65]=32'hD7A3C76B;
        sbox2[8'h66]=32'h3C11183B;
        sbox2[8'h67]=32'h5924A509;
        sbox2[8'h68]=32'hF28FE6ED;
        sbox2[8'h69]=32'h97F1FBFA;
        sbox2[8'h6a]=32'h9EBABF2C;
        sbox2[8'h6b]=32'h1E153C6E;
        sbox2[8'h6c]=32'h86E34570;
        sbox2[8'h6d]=32'hEAE96FB1;
        sbox2[8'h6e]=32'h860E5E0A;
        sbox2[8'h6f]=32'h5A3E2AB3;
        
        sbox2[8'h70]=32'h771FE71C;
        sbox2[8'h71]=32'h4E3D06FA;
        sbox2[8'h72]=32'h2965DCB9;
        sbox2[8'h73]=32'h99E71D0F;
        sbox2[8'h74]=32'h803E89D6;
        sbox2[8'h75]=32'h5266C825;
        sbox2[8'h76]=32'h2E4CC978;
        sbox2[8'h77]=32'h9C10B36A;
        sbox2[8'h78]=32'hC6150EBA;
        sbox2[8'h79]=32'h94E2EA78;
        sbox2[8'h7a]=32'hA5FC3C53;
        sbox2[8'h7b]=32'h1E0A2DF4;
        sbox2[8'h7c]=32'hF2F74EA7;
        sbox2[8'h7d]=32'h361D2B3D;
        sbox2[8'h7e]=32'h1939260F;
        sbox2[8'h7f]=32'h19C27960;
        
        sbox2[8'h80]=32'h5223A708;
        sbox2[8'h81]=32'hF71312B6;
        sbox2[8'h82]=32'hEBADFE6E;
        sbox2[8'h83]=32'hEAC31F66;
        sbox2[8'h84]=32'hE3BC4595;
        sbox2[8'h85]=32'hA67BC883;
        sbox2[8'h86]=32'hB17F37D1;
        sbox2[8'h87]=32'h018CFF28;
        sbox2[8'h88]=32'hC332DDEF;
        sbox2[8'h89]=32'hBE6C5AA5;
        sbox2[8'h8a]=32'h65582185;
        sbox2[8'h8b]=32'h68AB9802;
        sbox2[8'h8c]=32'hEECEA50F;
        sbox2[8'h8d]=32'hDB2F953B;
        sbox2[8'h8e]=32'h2AEF7DAD;
        sbox2[8'h8f]=32'h5B6E2F84;
        
        sbox2[8'h90]=32'h1521B628;
        sbox2[8'h91]=32'h29076170;
        sbox2[8'h92]=32'hECDD4775;
        sbox2[8'h93]=32'h619F1510;
        sbox2[8'h94]=32'h13CCA830;
        sbox2[8'h95]=32'hEB61BD96;
        sbox2[8'h96]=32'h0334FE1E;
        sbox2[8'h97]=32'hAA0363CF;
        sbox2[8'h98]=32'hB5735C90;
        sbox2[8'h99]=32'h4C70A239;
        sbox2[8'h9a]=32'hD59E9E0B;
        sbox2[8'h9b]=32'hCBAADE14;
        sbox2[8'h9c]=32'hEECC86BC;
        sbox2[8'h9d]=32'h60622CA7;
        sbox2[8'h9e]=32'h9CAB5CAB;
        sbox2[8'h9f]=32'hB2F3846E;
        
        sbox2[8'ha0]=32'h648B1EAF;
        sbox2[8'ha1]=32'h19BDF0CA;
        sbox2[8'ha2]=32'hA02369B9;
        sbox2[8'ha3]=32'h655ABB50;
        sbox2[8'ha4]=32'h40685A32;
        sbox2[8'ha5]=32'h3C2AB4B3;
        sbox2[8'ha6]=32'h319EE9D5;
        sbox2[8'ha7]=32'hC021B8F7;
        sbox2[8'ha8]=32'h9B540B19;
        sbox2[8'ha9]=32'h875FA099;
        sbox2[8'haa]=32'h95F7997E;
        sbox2[8'hab]=32'h623D7DA8;
        sbox2[8'hac]=32'hF837889A;
        sbox2[8'had]=32'h97E32D77;
        sbox2[8'hae]=32'h11ED935F;
        sbox2[8'haf]=32'h16681281;
        
        sbox2[8'hb0]=32'h0E358829;
        sbox2[8'hb1]=32'hC7E61FD6;
        sbox2[8'hb2]=32'h96DEDFA1;
        sbox2[8'hb3]=32'h7858BA99;
        sbox2[8'hb4]=32'h57F584A5;
        sbox2[8'hb5]=32'h1B227263;
        sbox2[8'hb6]=32'h9B83C3FF;
        sbox2[8'hb7]=32'h1AC24696;
        sbox2[8'hb8]=32'hCDB30AEB;
        sbox2[8'hb9]=32'h532E3054;
        sbox2[8'hba]=32'h8FD948E4;
        sbox2[8'hbb]=32'h6DBC3128;
        sbox2[8'hbc]=32'h58EBF2EF;
        sbox2[8'hbd]=32'h34C6FFEA;
        sbox2[8'hbe]=32'hFE28ED61;
        sbox2[8'hbf]=32'hEE7C3C73;
        
        sbox2[8'hc0]=32'h5D4A14D9;
        sbox2[8'hc1]=32'hE864B7E3;
        sbox2[8'hc2]=32'h42105D14;
        sbox2[8'hc3]=32'h203E13E0;
        sbox2[8'hc4]=32'h45EEE2B6;
        sbox2[8'hc5]=32'hA3AAABEA;
        sbox2[8'hc6]=32'hDB6C4F15;
        sbox2[8'hc7]=32'hFACB4FD0;
        sbox2[8'hc8]=32'hC742F442;
        sbox2[8'hc9]=32'hEF6ABBB5;
        sbox2[8'hca]=32'h654F3B1D;
        sbox2[8'hcb]=32'h41CD2105;
        sbox2[8'hcc]=32'hD81E799E;
        sbox2[8'hcd]=32'h86854DC7;
        sbox2[8'hce]=32'hE44B476A;
        sbox2[8'hcf]=32'h3D816250;
        
        sbox2[8'hd0]=32'hCF62A1F2;
        sbox2[8'hd1]=32'h5B8D2646;
        sbox2[8'hd2]=32'hFC8883A0;
        sbox2[8'hd3]=32'hC1C7B6A3;
        sbox2[8'hd4]=32'h7F1524C3;
        sbox2[8'hd5]=32'h69CB7492;
        sbox2[8'hd6]=32'h47848A0B;
        sbox2[8'hd7]=32'h5692B285;
        sbox2[8'hd8]=32'h095BBF00;
        sbox2[8'hd9]=32'hAD19489D;
        sbox2[8'hda]=32'h1462B174;
        sbox2[8'hdb]=32'h23820E00;
        sbox2[8'hdc]=32'h58428D2A;
        sbox2[8'hdd]=32'h0C55F5EA;
        sbox2[8'hde]=32'h1DADF43E;
        sbox2[8'hdf]=32'h233F7061;
        
        sbox2[8'he0]=32'h3372F092;
        sbox2[8'he1]=32'h8D937E41;
        sbox2[8'he2]=32'hD65FECF1;
        sbox2[8'he3]=32'h6C223BDB;
        sbox2[8'he4]=32'h7CDE3759;
        sbox2[8'he5]=32'hCBEE7460;
        sbox2[8'he6]=32'h4085F2A7;
        sbox2[8'he7]=32'hCE77326E;
        sbox2[8'he8]=32'hA6078084;
        sbox2[8'he9]=32'h19F8509E;
        sbox2[8'hea]=32'hE8EFD855;
        sbox2[8'heb]=32'h61D99735;
        sbox2[8'hec]=32'hA969A7AA;
        sbox2[8'hed]=32'hC50C06C2;
        sbox2[8'hee]=32'h5A04ABFC;
        sbox2[8'hef]=32'h800BCADC;
        
        sbox2[8'hf0]=32'h9E447A2E;
        sbox2[8'hf1]=32'hC3453484;
        sbox2[8'hf2]=32'hFDD56705;
        sbox2[8'hf3]=32'h0E1E9EC9;
        sbox2[8'hf4]=32'hDB73DBD3;
        sbox2[8'hf5]=32'h105588CD;
        sbox2[8'hf6]=32'h675FDA79;
        sbox2[8'hf7]=32'hE3674340;
        sbox2[8'hf8]=32'hC5C43465;
        sbox2[8'hf9]=32'h713E38D8;
        sbox2[8'hfa]=32'h3D28F89E;
        sbox2[8'hfb]=32'hF16DFF20;
        sbox2[8'hfc]=32'h153E21E7;
        sbox2[8'hfd]=32'h8FB03D4A;
        sbox2[8'hfe]=32'hE6E39F2B;
        sbox2[8'hff]=32'hDB83ADF7;
            //Sbox-3
            
            sbox3[8'h00]=32'hE93D5A68;
            sbox3[8'h01]=32'h948140F7;
            sbox3[8'h02]=32'hF64C261C;
            sbox3[8'h03]=32'h94692934;
            sbox3[8'h04]=32'h411520F7;
            sbox3[8'h05]=32'h7602D4F7;
            sbox3[8'h06]=32'hBCF46B2E;
            sbox3[8'h07]=32'hD4A20068;
            sbox3[8'h08]=32'hD4082471;
            sbox3[8'h09]=32'h3320F46A;
            sbox3[8'h0a]=32'h43B7D4B7;
            sbox3[8'h0b]=32'h500061AF;
            sbox3[8'h0c]=32'h1E39F62E;
            sbox3[8'h0d]=32'h97244546;
            sbox3[8'h0e]=32'h14214F74;
            sbox3[8'h0f]=32'hBF8B8840;
            
            sbox3[8'h10]=32'h4D95FC1D;
            sbox3[8'h11]=32'h96B591AF;
            sbox3[8'h12]=32'h70F4DDD3;
            sbox3[8'h13]=32'h66A02F45;
            sbox3[8'h14]=32'hBFBC09EC;
            sbox3[8'h15]=32'h03BD9785;
            sbox3[8'h16]=32'h7FAC6DD0;
            sbox3[8'h17]=32'h31CB8504;
            sbox3[8'h18]=32'h96EB27B3;
            sbox3[8'h19]=32'h55FD3941;
            sbox3[8'h1a]=32'hDA2547E6;
            sbox3[8'h1b]=32'hABCA0A9A;
            sbox3[8'h1c]=32'h28507825;
            sbox3[8'h1d]=32'h530429F4;
            sbox3[8'h1e]=32'h0A2C86DA;
            sbox3[8'h1f]=32'hE9B66DFB;
            
            sbox3[8'h20]=32'h68DC1462;
            sbox3[8'h21]=32'hD7486900;
            sbox3[8'h22]=32'h680EC0A4;
            sbox3[8'h23]=32'h27A18DEE;
            sbox3[8'h24]=32'h4F3FFEA2;
            sbox3[8'h25]=32'hE887AD8C;
            sbox3[8'h26]=32'hB58CE006;
            sbox3[8'h27]=32'h7AF4D6B6;
            sbox3[8'h28]=32'hAACE1E7C;
            sbox3[8'h29]=32'hD3375FEC;
            sbox3[8'h2a]=32'hCE78A399;
            sbox3[8'h2b]=32'h406B2A42;
            sbox3[8'h2c]=32'h20FE9E35;
            sbox3[8'h2d]=32'hD9F385B9;
            sbox3[8'h2e]=32'hEE39D7AB;
            sbox3[8'h2f]=32'h3B124E8B;
            
            sbox3[8'h30]=32'h1DC9FAF7;
            sbox3[8'h31]=32'h4B6D1856;
            sbox3[8'h32]=32'h26A36631;
            sbox3[8'h33]=32'hEAE397B2;
            sbox3[8'h34]=32'h3A6EFA74;
            sbox3[8'h35]=32'hDD5B4332;
            sbox3[8'h36]=32'h6841E7F7;
            sbox3[8'h37]=32'hCA7820FB;
            sbox3[8'h38]=32'hFB0AF54E;
            sbox3[8'h39]=32'hD8FEB397;
            sbox3[8'h3a]=32'h454056AC;
            sbox3[8'h3b]=32'hBA489527;
            sbox3[8'h3c]=32'h55533A3A;
            sbox3[8'h3d]=32'h20838D87;
            sbox3[8'h3e]=32'hFE6BA9B7;
            sbox3[8'h3f]=32'hD096954B;
            
            sbox3[8'h40]=32'h55A867BC;
            sbox3[8'h41]=32'hA1159A58;
            sbox3[8'h42]=32'hCCA92963;
            sbox3[8'h43]=32'h99E1DB33;
            sbox3[8'h44]=32'hA62A4A56;
            sbox3[8'h45]=32'h3F3125F9;
            sbox3[8'h46]=32'h5EF47E1C;
            sbox3[8'h47]=32'h9029317C;
            sbox3[8'h48]=32'hFDF8E802;
            sbox3[8'h49]=32'h04272F70;
            sbox3[8'h4a]=32'h80BB155C;
            sbox3[8'h4b]=32'h05282CE3;
            sbox3[8'h4c]=32'h95C11548;
            sbox3[8'h4d]=32'hE4C66D22;
            sbox3[8'h4e]=32'h48C1133F;
            sbox3[8'h4f]=32'hC70F86DC;
            
            sbox3[8'h50]=32'h07F9C9EE;
            sbox3[8'h51]=32'h41041F0F;
            sbox3[8'h52]=32'h404779A4;
            sbox3[8'h53]=32'h5D886E17;
            sbox3[8'h54]=32'h325F51EB;
            sbox3[8'h55]=32'hD59BC0D1;
            sbox3[8'h56]=32'hF2BCC18F;
            sbox3[8'h57]=32'h41113564;
            sbox3[8'h58]=32'h257B7834;
            sbox3[8'h59]=32'h602A9C60;
            sbox3[8'h5a]=32'hDFF8E8A3;
            sbox3[8'h5b]=32'h1F636C1B;
            sbox3[8'h5c]=32'h0E12B4C2;
            sbox3[8'h5d]=32'h02E1329E;
            sbox3[8'h5e]=32'hAF664FD1;
            sbox3[8'h5f]=32'hCAD18115;
            
            sbox3[8'h60]=32'h6B2395E0;
            sbox3[8'h61]=32'h333E92E1;
            sbox3[8'h62]=32'h3B240B62;
            sbox3[8'h63]=32'hEEBEB922;
            sbox3[8'h64]=32'h85B2A20E;
            sbox3[8'h65]=32'hE6BA0D99;
            sbox3[8'h66]=32'hDE720C8C;
            sbox3[8'h67]=32'h2DA2F728;
            sbox3[8'h68]=32'hD0127845;
            sbox3[8'h69]=32'h95B794FD;
            sbox3[8'h6a]=32'h647D0862;
            sbox3[8'h6b]=32'hE7CCF5F0;
            sbox3[8'h6c]=32'h5449A36F;
            sbox3[8'h6d]=32'h877D48FA;
            sbox3[8'h6e]=32'hC39DFD27;
            sbox3[8'h6f]=32'hF33E8D1E;
            
            sbox3[8'h70]=32'h0A476341;
            sbox3[8'h71]=32'h992EFF74;
            sbox3[8'h72]=32'h3A6F6EAB;
            sbox3[8'h73]=32'hF4F8FD37;
            sbox3[8'h74]=32'hA812DC60;
            sbox3[8'h75]=32'hA1EBDDF8;
            sbox3[8'h76]=32'h991BE14C;
            sbox3[8'h77]=32'hDB6E6B0D;
            sbox3[8'h78]=32'hC67B5510;
            sbox3[8'h79]=32'h6D672C37;
            sbox3[8'h7a]=32'h2765D43B;
            sbox3[8'h7b]=32'hDCD0E804;
            sbox3[8'h7c]=32'hF1290DC7;
            sbox3[8'h7d]=32'hCC00FFA3;
            sbox3[8'h7e]=32'hB5390F92;
            sbox3[8'h7f]=32'h690FED0B;
            
            sbox3[8'h80]=32'h667B9FFB;
            sbox3[8'h81]=32'hCEDB7D9C;
            sbox3[8'h82]=32'hA091CF0B;
            sbox3[8'h83]=32'hD9155EA3;
            sbox3[8'h84]=32'hBB132F88;
            sbox3[8'h85]=32'h515BAD24;
            sbox3[8'h86]=32'h7B9479BF;
            sbox3[8'h87]=32'h763BD6EB;
            sbox3[8'h88]=32'h37392EB3;
            sbox3[8'h89]=32'hCC115979;
            sbox3[8'h8a]=32'h8026E297;
            sbox3[8'h8b]=32'hF42E312D;
            sbox3[8'h8c]=32'h6842ADA7;
            sbox3[8'h8d]=32'hC66A2B3B;
            sbox3[8'h8e]=32'h12754CCC;
            sbox3[8'h8f]=32'h782EF11C;
            
            sbox3[8'h90]=32'h6A124237;
            sbox3[8'h91]=32'hB79251E7;
            sbox3[8'h92]=32'h06A1BBE6;
            sbox3[8'h93]=32'h4BFB6350;
            sbox3[8'h94]=32'h1A6B1018;
            sbox3[8'h95]=32'h11CAEDFA;
            sbox3[8'h96]=32'h3D25BDD8;
            sbox3[8'h97]=32'hE2E1C3C9;
            sbox3[8'h98]=32'h44421659;
            sbox3[8'h99]=32'h0A121386;
            sbox3[8'h9a]=32'hD90CEC6E;
            sbox3[8'h9b]=32'hD5ABEA2A;
            sbox3[8'h9c]=32'h64AF674E;
            sbox3[8'h9d]=32'hDA86A85F;
            sbox3[8'h9e]=32'hBEBFE988;
            sbox3[8'h9f]=32'h64E4C3FE;
            
            sbox3[8'ha0]=32'h9DBC8057;
            sbox3[8'ha1]=32'hF0F7C086;
            sbox3[8'ha2]=32'h60787BF8;
            sbox3[8'ha3]=32'h6003604D;
            sbox3[8'ha4]=32'hD1FD8346;
            sbox3[8'ha5]=32'hF6381FB0;
            sbox3[8'ha6]=32'h7745AE04;
            sbox3[8'ha7]=32'hD736FCCC;
            sbox3[8'ha8]=32'h83426B33;
            sbox3[8'ha9]=32'hF01EAB71;
            sbox3[8'haa]=32'hB0804187;
            sbox3[8'hab]=32'h3C005E5F;
            sbox3[8'hac]=32'h77A057BE;
            sbox3[8'had]=32'hBDE8AE24;
            sbox3[8'hae]=32'h55464299;
            sbox3[8'haf]=32'hBF582E61;
            
            sbox3[8'hb0]=32'h4E58F48F;
            sbox3[8'hb1]=32'hF2DDFDA2;
            sbox3[8'hb2]=32'hF474EF38;
            sbox3[8'hb3]=32'h8789BDC2;
            sbox3[8'hb4]=32'h5366F9C3;
            sbox3[8'hb5]=32'hC8B38E74;
            sbox3[8'hb6]=32'hB475F255;
            sbox3[8'hb7]=32'h46FCD9B9;
            sbox3[8'hb8]=32'h7AEB2661;
            sbox3[8'hb9]=32'h8B1DDF84;
            sbox3[8'hba]=32'h846A0E79;
            sbox3[8'hbb]=32'h915F95E2;
            sbox3[8'hbc]=32'h466E598E;
            sbox3[8'hbd]=32'h20B45770;
            sbox3[8'hbe]=32'h8CD55591;
            sbox3[8'hbf]=32'hC902DE4C;
            
            sbox3[8'hc0]=32'hB90BACE1;
            sbox3[8'hc1]=32'hBB8205D0;
            sbox3[8'hc2]=32'h11A86248;
            sbox3[8'hc3]=32'h7574A99E;
            sbox3[8'hc4]=32'hB77F19B6;
            sbox3[8'hc5]=32'hE0A9DC09;
            sbox3[8'hc6]=32'h662D09A1;
            sbox3[8'hc7]=32'hC4324633;
            sbox3[8'hc8]=32'hE85A1F02;
            sbox3[8'hc9]=32'h09F0BE8C;
            sbox3[8'hca]=32'h4A99A025;
            sbox3[8'hcb]=32'h1D6EFE10;
            sbox3[8'hcc]=32'h1AB93D1D;
            sbox3[8'hcd]=32'h0BA5A4DF;
            sbox3[8'hce]=32'hA186F20F;
            sbox3[8'hcf]=32'h2868F169;
            
            sbox3[8'hd0]=32'hDCB7DA83;
            sbox3[8'hd1]=32'h573906FE;
            sbox3[8'hd2]=32'hA1E2CE9B;
            sbox3[8'hd3]=32'h4FCD7F52;
            sbox3[8'hd4]=32'h50115E01;
            sbox3[8'hd5]=32'hA70683FA;
            sbox3[8'hd6]=32'hA002B5C4;
            sbox3[8'hd7]=32'h0DE6D027;
            sbox3[8'hd8]=32'h9AF88C27;
            sbox3[8'hd9]=32'h773F8641;
            sbox3[8'hda]=32'hC3604C06;
            sbox3[8'hdb]=32'h61A806B5;
            sbox3[8'hdc]=32'hF0177A28;
            sbox3[8'hdd]=32'hC0F586E0;
            sbox3[8'hde]=32'h006058AA;
            sbox3[8'hdf]=32'h30DC7D62;
            
            sbox3[8'he0]=32'h11E69ED7;
            sbox3[8'he1]=32'h2338EA63;
            sbox3[8'he2]=32'h53C2DD94;
            sbox3[8'he3]=32'hC2C21634;
            sbox3[8'he4]=32'hBBCBEE56;
            sbox3[8'he5]=32'h90BCB6DE;
            sbox3[8'he6]=32'hEBFC7DA1;
            sbox3[8'he7]=32'hCE591D76;
            sbox3[8'he8]=32'h6F05E409;
            sbox3[8'he9]=32'h4B7C0188;
            sbox3[8'hea]=32'h39720A3D;
            sbox3[8'heb]=32'h7C927C24;
            sbox3[8'hec]=32'h86E3725F;
            sbox3[8'hed]=32'h724D9DB9;
            sbox3[8'hee]=32'h1AC15BB4;
            sbox3[8'hef]=32'hD39EB8FC;
            
            sbox3[8'hf0]=32'hED545578;
            sbox3[8'hf1]=32'h08FCA5B5;
            sbox3[8'hf2]=32'hD83D7CD3;
            sbox3[8'hf3]=32'h4DAD0FC4;
            sbox3[8'hf4]=32'h1E50EF5E;
            sbox3[8'hf5]=32'hB161E6F8;
            sbox3[8'hf6]=32'hA28514D9;
            sbox3[8'hf7]=32'h6C51133C;
            sbox3[8'hf8]=32'h6FD5C7E7;
            sbox3[8'hf9]=32'h56E14EC4;
            sbox3[8'hfa]=32'h362ABFCE;
            sbox3[8'hfb]=32'hDDC6C837;
            sbox3[8'hfc]=32'hD79A3234;
            sbox3[8'hfd]=32'h92638212;
            sbox3[8'hfe]=32'h670EFA8E;
            sbox3[8'hff]=32'h406000E0;
    
                             
            sbox4[8'h00]=32'h3A39CE37;
            sbox4[8'h01]=32'hD3FAF5CF;
            sbox4[8'h02]=32'hABC27737;
            sbox4[8'h03]=32'h5AC52D1B;
            sbox4[8'h04]=32'h5CB0679E;
            sbox4[8'h05]=32'h4FA33742;
            sbox4[8'h06]=32'hD3822740;
            sbox4[8'h07]=32'h99BC9BBE;
            sbox4[8'h08]=32'hD5118E9D;
            sbox4[8'h09]=32'hBF0F7315;
            sbox4[8'h0a]=32'hD62D1C7E;
            sbox4[8'h0b]=32'hC700C47B;
            sbox4[8'h0c]=32'hB78C1B6B;
            sbox4[8'h0d]=32'h21A19045;
            sbox4[8'h0e]=32'hB26EB1BE;
            sbox4[8'h0f]=32'h6A366EB4;
            
            sbox4[8'h10]=32'h5748AB2F;
            sbox4[8'h11]=32'hBC946E79;
            sbox4[8'h12]=32'hC6A376D2;
            sbox4[8'h13]=32'h6549C2C8;
            sbox4[8'h14]=32'h530FF8EE;
            sbox4[8'h15]=32'h468DDE7D;
            sbox4[8'h16]=32'hD5730A1D;
            sbox4[8'h17]=32'h4CD04DC6;
            sbox4[8'h18]=32'h2939BBDB;
            sbox4[8'h19]=32'hA9BA4650;
            sbox4[8'h1a]=32'hAC9526E8;
            sbox4[8'h1b]=32'hBE5EE304;
            sbox4[8'h1c]=32'hA1FAD5F0;
            sbox4[8'h1d]=32'h6A2D519A;
            sbox4[8'h1e]=32'h63EF8CE2;
            sbox4[8'h1f]=32'h9A86EE22;
            
            sbox4[8'h20]=32'hC089C2B8;
            sbox4[8'h21]=32'h43242EF6;
            sbox4[8'h22]=32'hA51E03AA;
            sbox4[8'h23]=32'h9CF2D0A4;
            sbox4[8'h24]=32'h83C061BA;
            sbox4[8'h25]=32'h9BE96A4D;
            sbox4[8'h26]=32'h8FE51550;
            sbox4[8'h27]=32'hBA645BD6;
            sbox4[8'h28]=32'h2826A2F9;
            sbox4[8'h29]=32'hA73A3AE1;
            sbox4[8'h2a]=32'h4BA99586;
            sbox4[8'h2b]=32'hEF5562E9;
            sbox4[8'h2c]=32'hC72FEFD3;
            sbox4[8'h2d]=32'hF752F7DA;
            sbox4[8'h2e]=32'h3F046F69;
            sbox4[8'h2f]=32'h77FA0A59;
            
            sbox4[8'h30]=32'h80E4A915;
            sbox4[8'h31]=32'h87B08601;
            sbox4[8'h32]=32'h9B09E6AD;
            sbox4[8'h33]=32'h3B3EE593;
            sbox4[8'h34]=32'hE990FD5A;
            sbox4[8'h35]=32'h9E34D797;
            sbox4[8'h36]=32'h2CF0B7D9;
            sbox4[8'h37]=32'h022B8B51;
            sbox4[8'h38]=32'h96D5AC3A;
            sbox4[8'h39]=32'h017DA67D;
            sbox4[8'h3a]=32'hD1CF3ED6;
            sbox4[8'h3b]=32'h7C7D2D28;
            sbox4[8'h3c]=32'h1F9F25CF;
            sbox4[8'h3d]=32'hADF2B89B;
            sbox4[8'h3e]=32'h5AD6B472;
            sbox4[8'h3f]=32'h5A88F54C;
            
            sbox4[8'h40]=32'hE029AC71;
            sbox4[8'h41]=32'hE019A5E6;
            sbox4[8'h42]=32'h47B0ACFD;
            sbox4[8'h43]=32'hED93FA9B;
            sbox4[8'h44]=32'hE8D3C48D;
            sbox4[8'h45]=32'h283B57CC;
            sbox4[8'h46]=32'hF8D56629;
            sbox4[8'h47]=32'h79132E28;
            sbox4[8'h48]=32'h785F0191;
            sbox4[8'h49]=32'hED756055;
            sbox4[8'h4a]=32'hF7960E44;
            sbox4[8'h4b]=32'hE3D35E8C;
            sbox4[8'h4c]=32'h15056DD4;
            sbox4[8'h4d]=32'h88F46DBA;
            sbox4[8'h4e]=32'h03A16125;
            sbox4[8'h4f]=32'h0564F0BD;
            
            sbox4[8'h50]=32'hC3EB9E15;
            sbox4[8'h51]=32'h3C9057A2;
            sbox4[8'h52]=32'h97271AEC;
            sbox4[8'h53]=32'hA93A072A;
            sbox4[8'h54]=32'h1B3F6D9B;
            sbox4[8'h55]=32'h1E6321F5;
            sbox4[8'h56]=32'hF59C66FB;
            sbox4[8'h57]=32'h26DCF319;
            sbox4[8'h58]=32'h7533D928;
            sbox4[8'h59]=32'hB155FDF5;
            sbox4[8'h5a]=32'h03563482;
            sbox4[8'h5b]=32'h8ABA3CBB;
            sbox4[8'h5c]=32'h28517711;
            sbox4[8'h5d]=32'hC20AD9F8;
            sbox4[8'h5e]=32'hABCC5167;
            sbox4[8'h5f]=32'hCCAD925F;
            
            sbox4[8'h60]=32'h4DE81751;
            sbox4[8'h61]=32'h3830DC8E;
            sbox4[8'h62]=32'h379D5862;
            sbox4[8'h63]=32'h9320F991;
            sbox4[8'h64]=32'hEA7A90C2;
            sbox4[8'h65]=32'hFB3E7BCE;
            sbox4[8'h66]=32'h5121CE64;
            sbox4[8'h67]=32'h774FBE32;
            sbox4[8'h68]=32'hA8B6E37E;
            sbox4[8'h69]=32'hC3293D46;
            sbox4[8'h6a]=32'h48DE5369;
            sbox4[8'h6b]=32'h6413E680;
            sbox4[8'h6c]=32'hA2AE0810;
            sbox4[8'h6d]=32'hDD6DB224;
            sbox4[8'h6e]=32'h69852DFD;
            sbox4[8'h6f]=32'h09072166;
            
            sbox4[8'h70]=32'hB39A460A;
            sbox4[8'h71]=32'h6445C0DD;
            sbox4[8'h72]=32'h586CDECF;
            sbox4[8'h73]=32'h1C20C8AE;
            sbox4[8'h74]=32'h5BBEF7DD;
            sbox4[8'h75]=32'h1B588D40;
            sbox4[8'h76]=32'hCCD2017F;
            sbox4[8'h77]=32'h6BB4E3BB;
            sbox4[8'h78]=32'hDDA26A7E;
            sbox4[8'h79]=32'h3A59FF45;
            sbox4[8'h7a]=32'h3E350A44;
            sbox4[8'h7b]=32'hBCB4CDD5;
            sbox4[8'h7c]=32'h72EACEA8;
            sbox4[8'h7d]=32'hFA6484BB;
            sbox4[8'h7e]=32'h8D6612AE;
            sbox4[8'h7f]=32'hBF3C6F47;
            
            sbox4[8'h80]=32'hD29BE463;
            sbox4[8'h81]=32'h542F5D9E;
            sbox4[8'h82]=32'hAEC2771B;
            sbox4[8'h83]=32'hF64E6370;
            sbox4[8'h84]=32'h740E0D8D;
            sbox4[8'h85]=32'hE75B1357;
            sbox4[8'h86]=32'hF8721671;
            sbox4[8'h87]=32'hAF537D5D;
            sbox4[8'h88]=32'h4040CB08;
            sbox4[8'h89]=32'h4EB4E2CC;
            sbox4[8'h8a]=32'h34D2466A;
            sbox4[8'h8b]=32'h0115AF84;
            sbox4[8'h8c]=32'hE1B00428;
            sbox4[8'h8d]=32'h95983A1D;
            sbox4[8'h8e]=32'h06B89FB4;
            sbox4[8'h8f]=32'hCE6EA048;
            
            sbox4[8'h90]=32'h6F3F3B82;
            sbox4[8'h91]=32'h3520AB82;
            sbox4[8'h92]=32'h011A1D4B;
            sbox4[8'h93]=32'h277227F8;
            sbox4[8'h94]=32'h611560B1;
            sbox4[8'h95]=32'hE7933FDC;
            sbox4[8'h96]=32'hBB3A792B;
            sbox4[8'h97]=32'h344525BD;
            sbox4[8'h98]=32'hA08839E1;
            sbox4[8'h99]=32'h51CE794B;
            sbox4[8'h9a]=32'h2F32C9B7;
            sbox4[8'h9b]=32'hA01FBAC9;
            sbox4[8'h9c]=32'hE01CC87E;
            sbox4[8'h9d]=32'hBCC7D1F6;
            sbox4[8'h9e]=32'hCF0111C3;
            sbox4[8'h9f]=32'hA1E8AAC7;
            
            sbox4[8'ha0]=32'h1A908749;
            sbox4[8'ha1]=32'hD44FBD9A;
            sbox4[8'ha2]=32'hD0DADECB;
            sbox4[8'ha3]=32'hD50ADA38;
            sbox4[8'ha4]=32'h0339C32A;
            sbox4[8'ha5]=32'hC6913667;
            sbox4[8'ha6]=32'h8DF9317C;
            sbox4[8'ha7]=32'hE0B12B4F;
            sbox4[8'ha8]=32'hF79E59B7;
            sbox4[8'ha9]=32'h43F5BB3A;
            sbox4[8'haa]=32'hF2D519FF;
            sbox4[8'hab]=32'h27D9459C;
            sbox4[8'hac]=32'hBF97222C;
            sbox4[8'had]=32'h15E6FC2A;
            sbox4[8'hae]=32'h0F91FC71;
            sbox4[8'haf]=32'h9B941525;
            
            sbox4[8'hb0]=32'hFAE59361;
            sbox4[8'hb1]=32'hCEB69CEB;
            sbox4[8'hb2]=32'hC2A86459;
            sbox4[8'hb3]=32'h12BAA8D1;
            sbox4[8'hb4]=32'hB6C1075E;
            sbox4[8'hb5]=32'hE3056A0C;
            sbox4[8'hb6]=32'h10D25065;
            sbox4[8'hb7]=32'hCB03A442;
            sbox4[8'hb8]=32'hE0EC6E0E;
            sbox4[8'hb9]=32'h1698DB3B;
            sbox4[8'hba]=32'h4C98A0BE;
            sbox4[8'hbb]=32'h3278E964;
            sbox4[8'hbc]=32'h9F1F9532;
            sbox4[8'hbd]=32'hE0D392DF;
            sbox4[8'hbe]=32'hD3A0342B;
            sbox4[8'hbf]=32'h8971F21E;
            
            sbox4[8'hc0]=32'h1B0A7441;
            sbox4[8'hc1]=32'h4BA3348C;
            sbox4[8'hc2]=32'hC5BE7120;
            sbox4[8'hc3]=32'hC37632D8;
            sbox4[8'hc4]=32'hDF359F8D;
            sbox4[8'hc5]=32'h9B992F2E;
            sbox4[8'hc6]=32'hE60B6F47;
            sbox4[8'hc7]=32'h0FE3F11D ;
            sbox4[8'hc8]=32'hE54CDA54;
            sbox4[8'hc9]=32'h1EDAD891;
            sbox4[8'hca]=32'hCE6279CF;
            sbox4[8'hcb]=32'hCD3E7E6F;
            sbox4[8'hcc]=32'h1618B166;
            sbox4[8'hcd]=32'hFD2C1D05;
            sbox4[8'hce]=32'h848FD2C5;
            sbox4[8'hcf]=32'hF6FB2299;
            
            sbox4[8'hd0]=32'hF523F357;
            sbox4[8'hd1]=32'hA6327623;
            sbox4[8'hd2]=32'h93A83531;
            sbox4[8'hd3]=32'h56CCCD02;
            sbox4[8'hd4]=32'hACF08162;
            sbox4[8'hd5]=32'h5A75EBB5;
            sbox4[8'hd6]=32'h6E163697;
            sbox4[8'hd7]=32'h88D273CC;
            sbox4[8'hd8]=32'hDE966292;
            sbox4[8'hd9]=32'h81B949D0;
            sbox4[8'hda]=32'h4C50901B;
            sbox4[8'hdb]=32'h71C65614;
            sbox4[8'hdc]=32'hE6C6C7BD;
            sbox4[8'hdd]=32'h327A140A;
            sbox4[8'hde]=32'h45E1D006;
            sbox4[8'hdf]=32'hC3F27B9A;
            
            sbox4[8'he0]=32'hC9AA53FD;
            sbox4[8'he1]=32'h62A80F00;
            sbox4[8'he2]=32'hBB25BFE2;
            sbox4[8'he3]=32'h35BDD2F6;
            sbox4[8'he4]=32'h71126905;
            sbox4[8'he5]=32'hB2040222;
            sbox4[8'he6]=32'hB6CBCF7C;
            sbox4[8'he7]=32'hCD769C2B;
            sbox4[8'he8]=32'h53113EC0;
            sbox4[8'he9]=32'h1640E3D3;
            sbox4[8'hea]=32'h38ABBD60;
            sbox4[8'heb]=32'h2547ADF0;
            sbox4[8'hec]=32'hBA38209C;
            sbox4[8'hed]=32'hF746CE76;
            sbox4[8'hee]=32'h77AFA1C5;
            sbox4[8'hef]=32'h20756060;
            
            sbox4[8'hf0]=32'h85CBFE4E;
            sbox4[8'hf1]=32'h8AE88DD8;
            sbox4[8'hf2]=32'h7AAAF9B0;
            sbox4[8'hf3]=32'h4CF9AA7E;
            sbox4[8'hf4]=32'h1948C25C;
            sbox4[8'hf5]=32'h02FB8A8C;
            sbox4[8'hf6]=32'h01C36AE4;
            sbox4[8'hf7]=32'hD6EBE1F9;
            sbox4[8'hf8]=32'h90D4F869;
            sbox4[8'hf9]=32'hA65CDEA0;
            sbox4[8'hfa]=32'h3F09252D;
            sbox4[8'hfb]=32'hC208E69F;
            sbox4[8'hfc]=32'hB74E6132;
            sbox4[8'hfd]=32'hCE77E25B;
            sbox4[8'hfe]=32'h578FDFE3;
            sbox4[8'hff]=32'h3AC372E6;

    for (i=0;i<18;i=i+1)
        
    begin
            Pk[i]=P[i]^key[i%14];
    end
       
    end
    
     always @(din)
     begin 
     left[17]<=din[63:32];
     right[17]<=din[31:0];
     end
     
    always @(posedge clk)
    begin
    


    for (j=17;j>1;j=j-2)
    
    begin
    func(left[j],right[j],j,left[j-1],right[j-1]);
    func(right[j-1],left[j-1],j-1,right[j-2],left[j-2]);
     end

    left[0]<=right[1]^Pk[0];
    right[0]<=left[1]^Pk[1];
    dout={left[0],right[0]};
    end
   
task func(input[31:0] l,input[31:0] r,input[31:0] k,output[31:0] l1,output[31:0] r1);
begin

  l1=l^Pk[k];
 
  s1=l1[31:24];
  s2=l1[23:16];
  s3=l1[15:8];
  s4=l1[7:0];
  
  out1=sbox1[s1];
  out2=sbox2[s2];
  out3=sbox3[s3];
  out4=sbox4[s4];

  o1=out1+out2;
  o2=o1^out3;
  o3=o2+out4;
  
  r1=o3^r;
 
end

endtask
   

endmodule
