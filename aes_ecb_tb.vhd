library ieee;
use ieee.std_logic_1164.all;
use work.aes_pkg.all;
use work.aes_func.all;
use std.env.all;
use ieee.std_logic_textio.all;

-- test vectors found here: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf

entity aes_ecb_tb is
end aes_ecb_tb;

architecture rtl of aes_ecb_tb is

    constant ZERO_BLOCK             : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0) := X"00000000_00000000_00000000_00000000";
    signal fsm_reset                : std_logic := '1';
    signal fsm_clk                  : std_logic := '1';
    signal fsm_aes_mode             : std_logic_vector(1 downto 0) := "00"; --aes mode 128 (aes_pkg.vhd)
    signal fsm_aes_key_word_val     : std_logic_vector(3 downto 0) := "0100"; -- number of words in key (Nk = 4 for AES 128
    signal fsm_aes_key              : std_logic_vector(AES_256_KEY_WIDTH_C-1 downto 0);
    signal fsm_pipe_reset           : std_logic := '1';
    signal fsm_plain_text_val       : std_logic := '1';
    signal fsm_plain_text           : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0);
    signal fsm_cipher_ack           : std_logic := '0';
    signal fsm_cipher_val           : std_logic;
    signal fsm_cipher_text          : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0);
    signal fsm_ecb_busy             : std_logic;

    signal ct1, ct2, ct3, ct4       : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0) := ZERO_BLOCK;
    type state_type_data_sample_ctl is (IDLE, SAMPLE, DONE);
    signal data_sample_fsm          : state_type_data_sample_ctl := IDLE;

    component aes_ecb is
        generic(
            aes_n_rounds_g              : natural range 0 to NR_256_C   := NR_128_C);
        port(
            rst_i                       : in  std_logic;
            clk_i                       : in  std_logic;
            aes_mode_i                  : in  std_logic_vector(1 downto 0);
            aes_key_word_val_i          : in  std_logic_vector(3 downto 0);
            aes_key_word_i              : in  std_logic_vector(AES_256_KEY_WIDTH_C-1 downto 0);
            aes_pipe_reset_i            : in  std_logic;
            aes_plain_text_val_i        : in  std_logic;
            aes_plain_text_i            : in  std_logic_vector(aes_DATA_WIDTH_C-1 downto 0);
            aes_cipher_text_ack_i       : in  std_logic;
            aes_cipher_text_val_o       : out std_logic;
            aes_cipher_text_o           : out std_logic_vector(aes_DATA_WIDTH_C-1 downto 0);
            aes_ecb_busy_o              : out std_logic
            );
    end component;

begin

    dut : aes_ecb port map (
        rst_i                   => fsm_reset,
        clk_i                   => fsm_clk,
        aes_mode_i              => fsm_aes_mode,
        aes_key_word_val_i      => fsm_aes_key_word_val,
        aes_key_word_i          => fsm_aes_key,
        aes_pipe_reset_i        => fsm_pipe_reset,
        aes_plain_text_val_i    => fsm_plain_text_val,
        aes_plain_text_i        => fsm_plain_text,
        aes_cipher_text_ack_i   => fsm_cipher_ack, -- this is the last round ack not the ack that data is ready
        aes_cipher_text_val_o   => fsm_cipher_val,
        aes_cipher_text_o       => fsm_cipher_text,
        aes_ecb_busy_o          => fsm_ecb_busy
    );

    -- insert key value (left justified)
    fsm_aes_key(AES_256_KEY_WIDTH_C-1 downto 128) <= X"2B7E1516_28AED2A6_ABF71588_09CF4F3C";
    fsm_aes_key(127 downto 0) <= (others => '0');

    -- setup clock
    fsm_clk <= not fsm_clk after 500 ps;

    -- toggle resets after some initial hold off period 
    fsm_reset <= '1', '0' after 500 ps;
    fsm_pipe_reset <= '1', '0' after 500 ps;

    -- insert test vector
    fsm_plain_text         <=   ZERO_BLOCK,
                                X"6BC1BEE2_2E409F96_E93D7E11_7393172A" after 1 ns,
                                X"AE2D8A57_1E03AC9C_9EB76FAC_45AF8E51" after 2 ns,
                                X"30C81C46_A35CE411_E5FBC119_1A0A52EF" after 3 ns,
                                X"F69F2445_DF4F9B17_AD2B417B_E66C3710" after 4 ns;

    -- control feedback to ecb block
    fsm_cipher_ack <= '1' when fsm_cipher_val = '1' else '0';
   
        
 -- clock count driven       
    -- process
    -- begin
    --     for i in 0 to 35 loop 
    --         wait until rising_edge(fsm_clk); 
    --     end loop;
    --     stop;
    -- end process;

-- event driven sim controller
    process(fsm_clk)
    begin
        if fsm_clk'event and fsm_clk = '1' then

            case data_sample_fsm is
                when IDLE =>
                    if fsm_cipher_ack = '1' then
                        data_sample_fsm <= SAMPLE;
                    end if;

                when SAMPLE =>
                    if ct4 = ZERO_BLOCK then
                        ct1 <= fsm_cipher_text;
                        ct2 <= ct1;
                        ct3 <= ct2;
                        ct4 <= ct3;
                    else
                        data_sample_fsm <= DONE;
                    end if;

                when DONE =>
                    assert(ct1 = X"7B0C785E_27E8AD3F_82232071_04725DD4")
                        report "ct1 incorrect" severity error;
                    assert(ct2 = X"43B1CD7F_598ECE23_881B00E3_ED030688")
                        report "ct2 incorrect" severity error;
                    assert(ct3 = X"F5D3D585_03B9699D_E785895A_96FDBAAF")
                        report "ct3 incorrect" severity error;
                    assert(ct4 = X"3AD77BB4_0D7A3660_A89ECAF3_2466EF97")
                        report "ct4 incorrect" severity error;
                    
                    stop;
            end case;      
        
        end if;          
    end process;

end rtl;
