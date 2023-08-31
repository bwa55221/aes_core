library ieee;
use ieee.std_logic_1164.all;
use work.aes_pkg.all;
use work.aes_func.all;
use std.env.all;
use ieee.std_logic_textio.all;

entity aes_ecb_tb is
end aes_ecb_tb;

architecture rtl of aes_ecb_tb is

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

    signal test_reset               : std_logic := '1';
    signal test_clk                 : std_logic := '0';
    signal test_aes_mode            : std_logic_vector(1 downto 0) := "00"; --aes mode 128 (aes_pkg.vhd)
    signal test_aes_key_word_val    : std_logic_vector(3 downto 0) := "0100"; -- number of words in key (Nk = 4 for AES 128
    signal test_aes_key             : std_logic_vector(AES_256_KEY_WIDTH_C-1 downto 0);
    signal test_pipe_reset          : std_logic := '1';
    signal test_plain_text_val      : std_logic := '1';
    signal test_plain_text          : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0) := X"6BC1BEE2_2E409F96_E93D7E11_7393172A";
    signal test_cipher_ack          : std_logic := '0';
    signal test_cipher_val          : std_logic;
    signal test_cipher_text         : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0);
    signal test_ecb_busy            : std_logic;

    signal test_cipher_val_clkd     : std_logic := '0';

    type state_type_ack_control is (IDLE, ACK, END_ACK, SAMPLE_DATA, FINISHED);
    signal ACK_CONTROL_STATE        : state_type_ack_control := IDLE;

begin

    dut : aes_ecb port map (
            rst_i                   => test_reset,
            clk_i                   => test_clk,
            aes_mode_i              => test_aes_mode,
            aes_key_word_val_i      => test_aes_key_word_val,
            aes_key_word_i          => test_aes_key,
            aes_pipe_reset_i        => test_pipe_reset,
            aes_plain_text_val_i    => test_plain_text_val,
            aes_plain_text_i        => test_plain_text,
            aes_cipher_text_ack_i   => test_cipher_ack, -- this is the last round ack not the ack that data is ready
            aes_cipher_text_val_o   => test_cipher_val,
            aes_cipher_text_o       => test_cipher_text,
            aes_ecb_busy_o          => test_ecb_busy
    );

    -- initial key value (left justified)
    test_aes_key(AES_256_KEY_WIDTH_C-1 downto 128) <= X"2B7E1516_28AED2A6_ABF71588_09CF4F3C";
    test_aes_key(127 downto 0) <= (others => '0');

    -- setup clock
    test_clk <= not test_clk after 500 ps;

-- ***** acking control ***********
    
-- registered / clocking of dependent output
    process(test_clk)
    begin
        if test_clk'event and test_clk = '1' then
            test_cipher_val_clkd <= test_cipher_val;
        end if;
    end process;

-- state machine to handle acking
    process(test_clk)
    begin
        if test_clk'event and test_clk = '1' then
            CASE ACK_CONTROL_STATE is

                WHEN IDLE =>
                    test_reset <= '0';
                    test_cipher_ack <= '0';
                    test_pipe_reset <= '0';

                    if (test_cipher_val_clkd = '1') then
                        ACK_CONTROL_STATE <= ACK;
                    end if;

                WHEN ACK =>
                    test_cipher_ack <= '1';
                    ACK_CONTROL_STATE <= END_ACK;

                WHEN END_ACK =>
                    test_cipher_ack <= '0';
                    ACK_CONTROL_STATE <= SAMPLE_DATA;

                WHEN SAMPLE_DATA =>
                    test_pipe_reset <= '1';
                    test_reset <= '1';     
                    
                    if test_cipher_text /= X"3AD77BB4_0D7A3660_A89ECAF3_2466EF97" then
                        report "The value of test_cipher_text does not match expected value.";
                    end if;        
                    
                    ACK_CONTROL_STATE <= FINISHED;

                WHEN FINISHED =>
                    stop;

                end case;

        end if;
    end process;

    stimulus : process
    begin
        for i in 0 to 25 loop 
            wait until rising_edge(test_clk); 
        end loop;
        stop;
    end process;


end rtl;
