/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <hello_world_ta.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

static char root_key; // define root, random keys
static char random_key;

static void Caesar(char* in, char* out, char key)
{
	for (int i = 0; in[i] != 0 ; i++)
	{
	if (isalpha(in[i]))
		if (isupper(in[i]))
		    out[i] = (in[i] - 65 + key) % 26 + 65;
		else
		    out[i] = (in[i] - 97 + key) % 26 + 97;
	else
		out[i] = in[i];
	}
}

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	
	root_key = 3; // set root key

	TEE_GenerateRandom(&random_key, sizeof(random_key));// gen random key
	random_key = random_key % 26; // set bound

	IMSG("root_key is : %d\n random_key is : %d", root_key, random_key);

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result enc_caesar(uint32_t param_types,
	TEE_Param params[4])
{	
	// CA <-> TA parameter
	char * in_str = (char *)params[0].memref.buffer; // plaintext buffer pointer 
	// TA -> CA parameter
	char * out_key = (char *)params[1].memref.buffer; // key buffer pointer
	char out_str[255] = {0,}; // ciphertext buffer

	memcpy(out_str, in_str, sizeof(out_str)); // init ciphertext to plaintext

	Caesar(in_str, out_str, random_key); // encrypt plaintext with random key

	memset(out_key, 0, 255); // clear key buffer to zero
	out_key[0] = (random_key + root_key) % 26; // Caesar encrypt random key using root key
	DMSG ("enc> out key :  %d", out_key[0]);
	memcpy(in_str, out_str, sizeof(out_str)); // set parameter to ciphertext

	return TEE_SUCCESS;
}

static TEE_Result dec_caesar(uint32_t param_types,
	TEE_Param params[4])
{
	// CA <-> TA parameter
	char * in_str = (char *)params[0].memref.buffer; // ciphertext buffer pointer
	char * in_key = (char *)params[1].memref.buffer; // root(random) keytext buffer
	char out_str[255] = {0,}; // plaintext buffer 

	char rnd_key; // random key temp variable

	memcpy(out_str, in_str, sizeof(out_str)); // init plaintext to ciphertext

	DMSG ("dec> in key :  %d", in_key[0]);

	rnd_key = (in_key[0] + (26-root_key)) % 26; // decrypt cipherkey with root key
	// it will be root(random) -> random key

	DMSG ("dec> rnd key :  %d", rnd_key);

	Caesar(in_str, out_str, (26-rnd_key)); // decrypt ciphertext with random key
	// it will be random(ciphertext) -> plaintext

	memcpy(in_str, out_str, sizeof(out_str)); // set parameter to plaintext

	return TEE_SUCCESS;
}
static TEE_Result enc_rsa(uint32_t param_types,
	TEE_Param params[4])
{
		
	char * in_str = (char *)params[0].memref.buffer;
	char out_str[255] = {0,};
	memcpy(out_str, in_str, sizeof(out_str));
	DMSG("========================Encryption========================\n");
	DMSG ("Plaintext :  %s", in_str);

	for (int i = 0; in_str[i] != 0 ; i++)
	{
	if (isalpha(in_str[i]))
	if (isupper(in_str[i]))
	    out_str[i] = (in_str[i] - 65 + 3) % 26 + 65;
	else
	    out_str[i] = (in_str[i] - 97 + 3) % 26 + 97;
	}

	DMSG ("Ciphertext :  %s", out_str);
	memcpy(in_str, out_str, sizeof(out_str));

	return TEE_SUCCESS;
}
static TEE_Result dec_rsa(uint32_t param_types,
	TEE_Param params[4])
{
		
	char * in_str = (char *)params[0].memref.buffer;
	char out_str[255] = {0,};

	DMSG("========================Encryption========================\n");
	DMSG ("Plaintext :  %s", in_str);

	for (int i = 0; in_str[i] != 0 ; i++)
	{

	if (isupper(in_str[i]))
	    out_str[i] = (in_str[i] - 65 - 3) % 26 + 65;
	else
	    out_str[i] = (in_str[i] - 97 - 3) % 26 + 97;
	}

	DMSG ("Ciphertext :  %s", out_str);

	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	
	// event dispatch
	switch (cmd_id) {
	case TA_EVENT_ENC_Caesar:
		return enc_caesar(param_types, params);
	case TA_EVENT_DEC_Caesar:
		return dec_caesar(param_types, params);
	case TA_EVENT_ENC_RSA:
		return enc_rsa(param_types, params);
	case TA_EVENT_DEC_RSA:
		return dec_rsa(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
