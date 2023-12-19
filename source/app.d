import vibe.vibe;
import vibe.http.server;
import vibe.web.web;
import vibe.data.bson;
import vibe.core.log;

void main()
{
	auto settings = new HTTPServerSettings;
	settings.port = 8080;
	settings.bindAddresses = ["::1", "127.0.0.1"];

	auto router = new URLRouter;
	router.registerRestInterface(new ServerAPI);


	auto listener = listenHTTP(settings, router);
	scope (exit)
	{
		listener.stopListening();
	}

	//logInfo("Please open http://127.0.0.1:8080/ in your browser.");
	
	runApplication();
}

import sharedinterface.serverinterface;
import sharedinterface.block;
import device;

class ServerAPI : IServerAPI
{
	private {
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

		import std.conv : to;
		import std.digest;
		import std.digest.sha;
		import std.stdio;


		// FIXME: make this into a list
		string m_pubkey_pem;

		SList!Block m_private_blocks;

		//SList!Device m_devices = SList!Device();

		// a list of Devices indexed by the pubkey
		Device[string] m_devices = null;

		Block decode_bson_block(Bson bson_block) @safe
		{
			Block b = Block.init;
			try
			{
				// writeln(bson_block);
				// long id = bson_block["id"].get!long;
				// logInfo("Got id " ~ id);
				// b.id = id;
				// b.genisisPubkey = 

				deserializeBson(b, bson_block);
				// writeln(b);
			}
			catch(Exception ex)
			{
				logError("Failed to decode bson");
			}
			return b;
		}

		Bson encode_bson_block(Block block)
		{
			return block.serializeToBson();
		}

		bool check_signature(string pubkey_pem, string message, string sig_hex)
		{
        	writeln(pubkey_pem);
			DataSourceMemory input_pub = DataSourceMemory(pubkey_pem);
			// writeln(input_pub.read(10));

			Unique!AutoSeededRNG rng = new AutoSeededRNG();
        	Unique!PublicKey restored_pub = x509_key.loadKey(cast(DataSource)input_pub);
			if (!restored_pub)
        	{
            	logError("Could not recover " ~ pubkey_pem ~ " public key");
        	}
        	else if (restored_pub.checkKey(rng, true) == false)
        	{
            	logError("Restored pubkey failed self tests " ~ pubkey_pem);
        	}
			logInfo("Pubkey restored, and self tests passed!");


			//auto publickey = x509_key.loadKey(datasource_mem);
			auto verifier = PKVerifier(restored_pub, "EMSA1(SHA-224)");
			//ubyte[] signature_bytes;

			writeln(sig_hex);

			writeln("trying the hexdecode");
			//hexDecode(signature_bytes.ptr, sig_hex.ptr, sig_hex.length);
			Vector!ubyte signature_bytes = hexDecode(sig_hex);
			
			//writeln(signature_bytes);

			auto message_bytes = cast(ubyte[])message;

			bool isVerified = verifier.verifyMessage(
						message_bytes.ptr, 
						message_bytes.length, 
						signature_bytes.ptr, 
						signature_bytes.length
					);
			
			if(isVerified)
			{
				logInfo("Signature is verified!");
			}

			return isVerified;
		}
	}


	void register_device(string pubkey_pem)
	{
		// m_pubkey_pem = pubkey_pem;
		// logInfo("Registered new Pubkey...");
		// logInfo(m_pubkey_pem);

		if (m_devices != null
		&&  pubkey_pem in m_devices)
		{
			logInfo("Device already registered!");
			return;
		}

		Device new_dev = new Device(pubkey_pem);
		m_devices[pubkey_pem] = new_dev;
	}

	void register_token(string pubkey, string token, string signature)
	{
		// TODO: Get device
		//Device dev = this.m_devices.front();
		
		auto dev = m_devices[pubkey];
		dev.register_token(token, signature);
	}

	@property void reschedule_token(string token, string signature)
	{

	}


	void create_genisis_block(string pubkey, Bson bson_data)
	{
		// Device dev = this.m_devices.front();
		auto dev = m_devices[pubkey];
		dev.create_genisis_block(bson_data);
	}


	void new_block(string pubkey, Bson bson_data)
	{
		auto dev = m_devices[pubkey];
		dev.new_block(bson_data);

		// Block new_block   = decode_bson_block(bson_data);
		// writeln(new_block);
		// string pubkey_pem = new_block.genisisPubkey;

		// ubyte   id = cast(ubyte)new_block.id;
		// ubyte[] previous_hash = cast(ubyte[])new_block.previousblock_hash;
		
		// // logError(to!string(id));
		// // logError(to!string(previous_hash));
		// // logError(toHexString(sha256Of(id ~ previous_hash)));

		// string message = toHexString(sha256Of(id ~ previous_hash)).idup;
		// // FIXME: check previous hash value

		// logInfo("Message is " ~ message);

		// // string message    = new_block.previousblock_hash;
		// string signature  = new_block.signature_bytes_hex;
		// logInfo("Signature is" ~ signature);

		// if (check_signature(pubkey_pem, message, signature))
		// {
		// 	m_private_blocks.insertFront(new_block);
		// 	writeln(m_private_blocks);
		// 	logInfo("Verified signature...");
		// }
		// else
		// {
		// 	//FIXME: log stuff here!
		// 	logError("Signature missmatch, failed to update block!");
		// }
	}

	Bson last_block(string pubkey)
	{
	// 	Block current_top = m_private_blocks.front();
	// 	Bson encoded_block = encode_bson_block(current_top);
	// 	return encoded_block;

		return Bson.emptyObject; 
	}
}



