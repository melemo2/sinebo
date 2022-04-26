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

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <hello_world_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_HELLO_WORLD_UUID;
	char plaintext[255] = {0,};
	char ciphertext[255] = {0,};
	char key[255] = {0,};
	FILE *fp;
	uint32_t err_origin;
	
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT,
					 TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = sizeof(plaintext);

	op.params[1].tmpref.buffer = key;
	op.params[1].tmpref.size = sizeof(key);

	uint32_t event_type = 0;

	// if event type is '-e(encryption)' then
	// set event_type flag first bit to 1 else(decryption) 0
	event_type |= (strcmp(argv[1], "-e") ? 1:0);
	// if event method is 'Caesar' then
	// set event_type flag second bit to 1 else(RSA) 0
	event_type |= (strcmp(argv[argc-1], "Caesar") ? 2:0);

	// open plaintext file
	fp = fopen(argv[2], "r");
	fgets(&plaintext, sizeof(plaintext), fp);
	fclose(fp);

	memcpy(op.params[0].tmpref.buffer, plaintext, sizeof(plaintext));

	if ((event_type & 1) == 1) // if event method is 'd' then load 'key file' and key file path 
				// must be included in third arugment  
	{
		fp = fopen(argv[3], "r");
		fgets(&key, sizeof(key), fp);
		fclose(fp);

		// copy key buffer to parameter 2
		memcpy(op.params[1].tmpref.buffer, key, sizeof(key));
	} 
	
	res = TEEC_InvokeCommand(&sess, event_type, &op,
				 &err_origin);

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	memcpy(ciphertext, op.params[0].tmpref.buffer, sizeof(ciphertext));

	if ((event_type & 1) == 0) // if event method is 'e' then save 'key file'
	{
		// save encrypted text
		fp = fopen(strcat(strtok(argv[2],"."), ".enc"), "w");
		fputs(ciphertext, fp);
		fclose(fp);

		// copy parameter 2 to key buffer
		memcpy(key, op.params[1].tmpref.buffer, sizeof(ciphertext));

		// save encrypted key
		fp = fopen(strcat(strtok(argv[2],"."), ".key"), "w");
		printf("received key is %d\n", key[0]);
		fputs(key, fp);
		fclose(fp);
	} else {
		// save decrypted text
		fp = fopen(strcat(strtok(argv[2],"."), ".dec"), "w");
		fputs(ciphertext , fp);
		fclose(fp);
	}

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
