`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 15.10.2022 10:43:29
// Design Name: 
// Module Name: tb1
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

module tb1(

    );
    reg clk=0,rst;
    reg [63:0]din;
    wire [63:0]dout;
    
    decrypt uut (clk,rst,din,dout);
    
    always #5 clk=~clk;
     
    initial 
    begin 
    din=64'hf5f75e29a8c28db9;
    end
    
endmodule
