module tb(

    );
    reg clk=0,rst;
    reg [63:0]din;
    wire [63:0]dout;
    
    encrypt uut (clk,rst,din,dout);
    
    always #5 clk=~clk;
     
    initial 
    begin 
    din=64'h87ad4a5452ca1d00;
    end
    
endmodule