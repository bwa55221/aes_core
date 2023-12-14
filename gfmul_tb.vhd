library ieee;
use ieee.std_logic_1164.all;
use work.gcm_pkg.all;
use work.aes_pkg.all;
use std.env.all;

entity gfmul_tb is
end gfmul_tb;

architecture rtl of gfmul_tb is

    component ghash_gfmul is
        port(
            gf_mult_h_i         : in  std_logic_vector(GCM_DATA_WIDTH_C-1 downto 0);
            gf_mult_x_i         : in  std_logic_vector(GCM_DATA_WIDTH_C-1 downto 0);
            gf_mult_y_o         : out std_logic_vector(GCM_DATA_WIDTH_C-1 downto 0));
    end component;

    constant ZERO_BLOCK         : std_logic_vector(GCM_DATA_WIDTH_C-1 downto 0) := X"00000000_00000000_00000000_00000000";
    signal h_tb, x_tb, y_tb     : std_logic_vector(GCM_DATA_WIDTH_C-1 downto 0) := ZERO_BLOCK;
    signal clk                  : std_logic := '1';


begin

    h_tb <= X"B83B5337_08BF535D_0AA6E529_80D53B78"; -- hash subkey
    x_tb <= X"3AD77BB4_0D7A3660_A89ECAF3_2466EF97"; -- AAD

    clk <= not clk after 500 ps;

    dut : ghash_gfmul port map (
        gf_mult_h_i     => h_tb,
        gf_mult_x_i     => x_tb,
        gf_mult_y_o     => y_tb
    );

    process
    begin
        for i in 0 to 1 loop
            wait until rising_edge(clk);
        end loop;
        stop;
    end process;

end rtl;
