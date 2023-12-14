library ieee;
use ieee.std_logic_1164.all;
use work.aes_pkg.all;
use work.aes_func.all;
use std.env.all;
use ieee.std_logic_textio.all;
use ieee.std_logic_unsigned.all;

entity aes_gcm_tb is
end aes_gcm_tb;

architecture rtl of aes_gcm_tb is

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

    component ghash_gfmul is
        port (
            gf_mult_h_i         : in  std_logic_vector(aes_DATA_WIDTH_C-1 downto 0);
            gf_mult_x_i         : in  std_logic_vector(aes_DATA_WIDTH_C-1 downto 0);
            gf_mult_y_o         : out std_logic_vector(aes_DATA_WIDTH_C-1 downto 0)
        );
    end component;


    constant ZERO_BLOCK             : std_logic_vector(127 downto 0) := X"00000000_00000000_00000000_00000000";

    signal ecb_reset               : std_logic := '1';
    signal ecb_clk                 : std_logic := '0';
    signal ecb_aes_mode            : std_logic_vector(1 downto 0) := "00"; --aes mode 128 (aes_pkg.vhd)
    signal ecb_aes_key_word_val    : std_logic_vector(3 downto 0) := "0100"; -- number of words in key (Nk = 4 for AES 128
    signal ecb_aes_key             : std_logic_vector(AES_256_KEY_WIDTH_C-1 downto 0);
    signal ecb_pipe_reset          : std_logic := '1';
    signal ecb_plain_text_val      : std_logic := '1';
    signal ecb_plain_text          : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0) := ZERO_BLOCK;
    signal ecb_cipher_ack          : std_logic := '0';
    signal ecb_cipher_val          : std_logic;
    signal ecb_cipher_text         : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0);
    signal ecb_ecb_busy            : std_logic;

    signal ecb_cipher_val_clkd     : std_logic := '0';
    signal hash_subkey              : std_logic_vector(127 downto 0) := ZERO_BLOCK;
    signal IV                       : std_logic_vector(95 downto 0) := X"CAFEBABE_FACEDBAD_DECAF888";

    signal global_clk               : std_logic := '0';
    signal global_rst               : std_logic := '0';

    type state_type_ack_control is (IDLE, START, ACK, END_ACK, SAMPLE_DATA, FINISHED);
    signal ECB_CONTROL_STATE        : state_type_ack_control := IDLE;

    
    -- gcm wrapper signals
    type state_type_gcm         is (IDLE, GEN_HASH_SUBKEY, GEN_HASH_SUBKEY_WAIT, GEN_PRECOUNTER, GCTR, GCTR_WAIT, GEN_TAG, FINISHED);
    signal GCM_FSM_STATE            : state_type_gcm := IDLE;

    signal GEN_SUBKEY_START_f       : std_logic := '0';
    signal GEN_SUBKEY_FINSHED_f     : std_logic := '0';

    signal PRECOUNTER               : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0) := ZERO_BLOCK;
    signal COUNT                    : std_logic_vector(31 downto 0) := X"0000_0001";

    signal GCTR_START_f             : std_logic := '0';
    signal GCTR_FINISHED_f          : std_logic := '0';
    signal ciphered_cb              : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0) := ZERO_BLOCK;
    signal CT_OUT                   : std_logic_vector(aes_DATA_WIDTH_C-1 downto 0) := ZERO_BLOCK;

    signal ghash_h                  : std_logic_vector(aes_DATA_WIDTH_C -1 downto 0) := ZERO_BLOCK;
    signal ghash_x                  : std_logic_vector(aes_DATA_WIDTH_C -1 downto 0) := ZERO_BLOCK;
    signal ghash_y                  : std_logic_vector(aes_DATA_WIDTH_C -1 downto 0) := ZERO_BLOCK;
    signal AAD                      : std_logic_vector(aes_DATA_WIDTH_C -1 downto 0) := X"3AD77BB4_0D7A3660_A89ECAF3_2466EF97";
    signal GHASH_COMPLETE_f         : std_logic := '0';

begin

    ecb_clk <= global_clk; -- connect global clock to ecb

    -- initial key value (left justified)
    ecb_aes_key(AES_256_KEY_WIDTH_C-1 downto 128) <= X"FEFFE992_8665731C_6D6A8F94_67308308";
    ecb_aes_key(127 downto 0) <= (others => '0');

    -- setup clock
    global_clk <= not global_clk after 500 ps;
    
    dut1 : ghash_gfmul port map(
        gf_mult_h_i             => ghash_h,
        gf_mult_x_i             => ghash_x,
        gf_mult_y_o             => ghash_y
    );

    dut2 : aes_ecb port map (
            rst_i                   => ecb_reset,
            clk_i                   => ecb_clk,
            aes_mode_i              => ecb_aes_mode,
            aes_key_word_val_i      => ecb_aes_key_word_val,
            aes_key_word_i          => ecb_aes_key,
            aes_pipe_reset_i        => ecb_pipe_reset,
            aes_plain_text_val_i    => ecb_plain_text_val,
            aes_plain_text_i        => ecb_plain_text,
            aes_cipher_text_ack_i   => ecb_cipher_ack, -- this is the last round ack not the ack that data is ready
            aes_cipher_text_val_o   => ecb_cipher_val,
            aes_cipher_text_o       => ecb_cipher_text,
            aes_ecb_busy_o          => ecb_ecb_busy
    );

    GCM_FSM : process(global_clk)
    begin
        if global_clk'event and global_clk = '1' then
            if global_rst = '1' then
                null;
            else
        
         CASE GCM_FSM_STATE is 

            when IDLE =>
                GCM_FSM_STATE <= GEN_HASH_SUBKEY;

            when GEN_HASH_SUBKEY =>
                GEN_SUBKEY_START_f <= '1';
                ecb_plain_text <= ZERO_BLOCK;
                GCM_FSM_STATE <= GEN_HASH_SUBKEY_WAIT;

            when GEN_HASH_SUBKEY_WAIT =>
                if GEN_SUBKEY_FINSHED_f = '1' then
                    GEN_SUBKEY_START_f <= '0';
                    GCM_FSM_STATE <= GEN_PRECOUNTER;
                    COUNT <= COUNT + X"1";
                end if;

            when GEN_PRECOUNTER =>
                PRECOUNTER(PRECOUNTER'high downto 32) <= IV;
                PRECOUNTER(31 downto 0) <= X"0000_0000" or COUNT;
                GCM_FSM_STATE <= GCTR;

            when GCTR =>
                -- COUNT <= COUNT + X"0000_0001";
                ecb_plain_text <= PRECOUNTER;
                GCTR_START_f <= '1';
                GCM_FSM_STATE <= GCTR_WAIT;

            when GCTR_WAIT =>
                if GCTR_FINISHED_f = '1' then
                    CT_OUT <= X"D9313225_F88406E5_A55909C5_AFF5269A" xor ciphered_cb;
                    GCTR_START_f <= '0';
                    GCM_FSM_STATE <= GEN_TAG;
                end if;

            when GEN_TAG =>
                ghash_h <= hash_subkey;
                ghash_x <= AAD or CT_OUT;
                if GHASH_COMPLETE_f = '1' then
                    GCM_FSM_STATE <= FINISHED;
                end if;

            when FINISHED =>
                stop;

        end CASE;

        end if;
    end if;
    end process;


-- AES ECB controller
    process(ecb_clk)
    begin
        if ecb_clk'event and ecb_clk = '1' then
            CASE ECB_CONTROL_STATE is

                WHEN IDLE =>

                    ecb_reset <= '1';
                    ecb_pipe_reset <= '1';
                    GEN_SUBKEY_FINSHED_f <= '0';
                    GCTR_FINISHED_f <= '0';

                    if GEN_SUBKEY_START_f = '1' or GCTR_START_f = '1' then
                        ECB_CONTROL_STATE <= START;
                    end if;

                WHEN START =>
                    ecb_reset <= '0';
                    ecb_cipher_ack <= '0';
                    ecb_pipe_reset <= '0';

                    if (ecb_cipher_val = '1') then
                        ECB_CONTROL_STATE <= ACK;
                    end if;

                WHEN ACK =>
                    ecb_cipher_ack <= '1';
                    ECB_CONTROL_STATE <= END_ACK;

                WHEN END_ACK =>
                    ecb_cipher_ack <= '0';
                    ECB_CONTROL_STATE <= SAMPLE_DATA;

                WHEN SAMPLE_DATA =>
                    
                    ecb_pipe_reset <= '1';
                    ecb_reset <= '1';  

                    if GEN_SUBKEY_START_f = '1' then
                        hash_subkey <= ecb_cipher_text;   
                    elsif GCTR_START_f = '1' then
                        ciphered_cb <= ecb_cipher_text;
                    end if;

                    ECB_CONTROL_STATE <= FINISHED;

                WHEN FINISHED =>
                    if GEN_SUBKEY_START_f = '1' then
                        GEN_SUBKEY_FINSHED_f <= '1';
                    elsif GCTR_START_f = '1' then
                        GCTR_FINISHED_f <= '1';
                    end if;
                    ECB_CONTROL_STATE <= IDLE;

                end case;

        end if;
    end process;

    process
    begin
        for i in 0 to 100 loop
            wait until rising_edge(global_clk);
        end loop;
        stop;
    end process;
    
end rtl;
