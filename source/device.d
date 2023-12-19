module device;

import sharedinterface.block;
import vibe.data.bson;

import std.container : SList;
import botan.rng.rng;
import botan.rng.auto_rng;
import memutils.unique;
import botan.pubkey.pubkey;
import botan.pubkey.algo.rsa;
import botan.pubkey.x509_key;
import botan.utils.types;

import botan.codec.hex;
import botan.filters.data_src;

import vibe.core.log;

import std.conv : to;
import std.digest;
import std.digest.sha;

class Device 
{
private:


    int m_block_coutner        = 1; 
    string m_public_key_pem    = null;
    string m_hashchain_token   = null;
    string m_current_boot_hash = null;

    Unique!PublicKey m_public_key;
	PKVerifier m_verifier;
    
    //SList!Block m_private_blocks;
    Array!Block m_private_blocks;


    bool decode_pubkey_pem(string pubkey_pem)
    {
        DataSourceMemory input_pub = DataSourceMemory(pubkey_pem);
        Unique!AutoSeededRNG rng = new AutoSeededRNG();

        try
        {
            this.m_public_key = x509_key.loadKey(cast(DataSource)input_pub);
            if (!this.m_public_key)
            {
                logError("Could not recover " ~ pubkey_pem ~ " public key");
                return false;
            }
            else if (this.m_public_key.checkKey(rng, true) == false)
            {
                logError("Restored pubkey failed self tests " ~ pubkey_pem);
                return false;
            }

            logInfo("Publickey restored, and self tests passed!");
            return true;
        }
        catch (Exception ex)
        {
            logError(ex.msg);
            return false;
        }
    }

    void create_internal_verifier()
    {
        m_verifier = PKVerifier(this.m_public_key, "EMSA1(SHA-224)");
    }

    // bool check_signature(Vector!ubyte * message_to_check, Vector!ubyte * signature)
    // {
    //     return m_verifier.verifyMessage(
    //         *message_to_check,
    //         *signature);
    // }

    bool check_hex_signature(string hex_message, string hex_signature)
    {
        //Vector!ubyte message_bytes = hexDecode(hex_message);
        ubyte[] message_bytes = cast(ubyte[])hex_message;

        Vector!ubyte signature_bytes = hexDecode(hex_signature);

        // return this.check_signature(&message_bytes, &signature_bytes);
    
        return this.m_verifier.verifyMessage(
            message_bytes.ptr,
            message_bytes.length,
            signature_bytes.ptr,
            signature_bytes.length
        );
    }

public:

    this(string pubkey_pem)
    {
        this.m_public_key_pem = pubkey_pem;
        this.m_private_blocks = Array!Block(); //SList!Block();
        
        // restore the public key
        if (!this.decode_pubkey_pem(this.m_public_key_pem))
        {
            // TODO: handle error in a sane way
            throw new Exception("Failed to decode transmitted pubkey!");
        }

        create_internal_verifier();
    }

    void register_token(string hex_token, string hex_signature)
    {
        if (!check_hex_signature(hex_token, hex_signature))
        {
            logError("Failed to validate signature for new hashchain token " ~ hex_token);
            logError("With signature " ~ hex_signature);
            return;
        }

        logInfo("Verified signature for new hashchain token " ~ hex_token);
        this.m_hashchain_token = hex_token;
    }

    bool create_genisis_block(Bson bson_encoded_data)
    {
        // Exit if no public key or hashchain token was 
        // registered before creating a genisis node!
        if (this.m_public_key_pem == null
        ||  this.m_hashchain_token == null)
        {
            logError("No pubkey or hashchain token was registerd before trying to create a new genisis block!");
            return false;
        }

        Block input_data = Block.init;
        deserializeBson(input_data, bson_encoded_data);
        
        Block genisis         = Block.init;
        genisis.id            = m_block_coutner;
        genisis.isGenisis     = true;
        genisis.genisisPubkey = this.m_public_key_pem;
        // TODO: fix this ... maybe?
        genisis.previousblock_hash  = null;
        genisis.signature_bytes_hex = input_data.signature_bytes_hex;
        genisis.bootHash            = input_data.bootHash;

        this.m_current_boot_hash    = input_data.bootHash;

        // FIXME: this is going to be a local one
        genisis.updateWithHashChainToken = this.m_hashchain_token;
        genisis.unix_time_stamp          = 0;

        logInfo("Created new Genisis block for device " ~ m_public_key_pem);
        logInfo("With boot hash value: " ~ genisis.bootHash);

        // Add the block to the internal list
        //this.m_private_blocks.insertFront(genisis);
        this.m_private_blocks.insertBack(genisis);

        // Increase the block counter!
        m_block_coutner++;
        return true;
    }

    void new_block(Bson bson_encoded_block)
    {
        Block new_block = Block.init;
        deserializeBson(new_block, bson_encoded_block);

        // get the last block
        if (m_block_coutner-1 <= 0)
        {
            logError("Tried to add a new block before generating a genisis node!");
            return;
        }
        import std.stdio;
        writeln(this.m_block_coutner, m_private_blocks.length);
        Block last_block = this.m_private_blocks[m_private_blocks.length-1];

        // calculate current current block value
        string previous_block_hash = calculatePrevBlockHash(last_block);
        string current_block_hash = calculateCurrBlockHash(new_block);
        
        new_block.current_block_hash = current_block_hash;

        // exit if previous block hash is not the same we got in the current block!
        if (new_block.previousblock_hash != previous_block_hash)
        {
            logError("The newblock.previousblock_hash is not the same as the one we calcualted!");
            logError(new_block.previousblock_hash ~ " != " ~ previous_block_hash);
            return;
        }

        // check the signature of the current block hash value which is current.id + previous_block_hash!
        string hex_current_block_signature = new_block.signature_bytes_hex;
        if (!check_hex_signature(current_block_hash, hex_current_block_signature))
        {
            // Failed to verify the signature of the current block!
            logError("Failed to verify the signature of the current block hash " ~ current_block_hash);
            return;
        }

        // handle updated boot hash
        string new_boot_hash = new_block.bootHash;
        if (new_boot_hash != this.m_current_boot_hash)
        {
            // validate the update using the hashchain token!
            string used_hash_chain_token = new_block.updateWithHashChainToken;
            
            if (used_hash_chain_token == this.m_hashchain_token)
            {
                logError("Hashchain token was reused, discarding block with new boot hash " ~ new_boot_hash);
                return;
            }

            // check if hashchain token is valid 
            string hex_calculated_current_hashchain_token = toHexString(sha256Of(new_block.updateWithHashChainToken)).idup;
            if (hex_calculated_current_hashchain_token != this.m_hashchain_token)
            {
                logError("The calculated hashchain token doesn't match the supplied one!");
                logError(hex_calculated_current_hashchain_token ~ " != " ~ this.m_hashchain_token);
                return;
            }

            logInfo(
                "Updated boot hash from " ~ this.m_current_boot_hash 
                ~ "\r\nto " ~ new_block.bootHash
                ~ "\r\n using token " ~ used_hash_chain_token);

            // all the checks passed!
            // update the chaintoken
            this.m_hashchain_token = used_hash_chain_token;
        }

        // insert the block into the list after 
        // all checks have passed
        new_block.id = m_block_coutner;
        prettyPrint(new_block);
        // this.m_private_blocks.insertBefore(new_block);
        this.m_private_blocks.insertBack(new_block);
        m_block_coutner++;
        logInfo("Added new block with hash value " ~ current_block_hash ~ " and previous hash value " ~ previous_block_hash);

    }

}

unittest
{
    immutable string pubkey_pem = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCw5AT6jiqJibn1IkwZ+AzOkjO/
J6FnxcReEJnT3SCqZaNGd8E4j8A1IduXOPq2HV/yNSVsgkExVj1UkNgtf5jxpWDP
hWpl8PbGBdwzCH0YyLX5zk+YlYsaa4lR2wtuxmSOrLGqUsjcv8+tbBp+zmgICdSg
UzKrkvqOQoh/CIuxTQIDAQAB
-----END PUBLIC KEY-----`;

    // immutable array chain tokens
    // 87D8C7FAF01DB7A7F64C13496EAD23606E1669CD5ACD0AF4D8128A8A7AFF72D5
    // 8F62E023F14BE5C7F188B75C721C5FE1713612CFE938C0442B413405F8BD0C86
    // 67C841ABF46966734758922C40F651873CCE6316BA6457DFEAD0F6D1F2FFDDD8
    // 69DA100F96CD38E1BDB3C290340D5A80C0DD85570528DD86AA6CC640A4EF25C8
    // F41F55F9AE7D0CDC44E1149FB44266FD1F39443C4B0C78A4538486E861CD9F67
    // 5EBC57A2AC7CF5247AF0639F34E0B1C426D766157839CB0804FC480BE5D967DE
    // 0EA6E058FEAD3B348697FA61F306FA8CAF5CD85C48CC2263026378AE942A367D
    // 9F414BB04A3FF00D5E2F26D7EEDB7B066341CB46FF8258AD16F539D7C83FC34A
    // EA8A983B3A58D7040928009CCFB0497BF468FCDFBAC9B5E461D2FD5A6F4D1270
    // 2F54D175197598E84AC3DBBA71E2F1DEB9997997AFED3883CAE102DF62B4C0B7
    immutable string last_chain_token = "2F54D175197598E84AC3DBBA71E2F1DEB9997997AFED3883CAE102DF62B4C0B7";
    immutable string chaintoken_signature = "428BA887CB05697C1E2DEFF9AE330E6E77B243717631E62E5570AE5AA3DBE1B066C2BB9D51E5BDB2857FCB3CE59F5AE2CCA0E06A2C0A69E617940DC8AB52F34F1D7A8EDDC81E4F728D8D3EEDF81E72BC51861FAA75460E74341504B6B802F5A47874F728ED949DEDDC0442E9472E76189775B4B991F27CEFCB4243F063F70F9B";

    Device dev = new Device(pubkey_pem);
    //assert(dev != null);


}
