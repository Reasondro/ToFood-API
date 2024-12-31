from llama_cpp import Llama


# GLOBAL VARIABLES
my_model_path = "./model/unsloth.Q4_K_M.gguf"
CONTEXT_SIZE = 10000


# LOAD THE MODEL
tofood_model = Llama(model_path=my_model_path, n_gpu_layer = -1, n_ctx=CONTEXT_SIZE)

# def generate_text_from_prompt(user_prompt,
#                              max_tokens = 300,
#                              temperature = 0.3,
#                              top_p = 0.1,
#                              echo = True,
#                              stop = ["Q", "\n"]):
#    # Define the parameters
#    model_output = tofood_model(
#        user_prompt,
#        max_tokens=max_tokens,
#        temperature=temperature,
#        top_p=top_p,
#        echo=echo,
#        stop=stop,
#    )


#    return model_output



if __name__ == "__main__":

   generation_kwargs = {
        "max_tokens":20000,
        "stop":["</s>"],
        "echo":False, # Echo the prompt in the output
        "top_k":1 # This is essentially greedy decoding, since the model will always return the highest-probability token. Set this value > 1 for sampling decoding
    }
    
   prompt ="""
   "instruction:     Cek resep ini. Kira-kira bagus nggak buat ditawarkan ke pelanggan kita? 'Yes' atau 'No,' plus saran ya."
    input: Resep:   Tahu Isi Sayur; Bahan Utama: Tahu Kopong; Bahan: Tahu kopong, wortel parut, tauge, buncis cincang, bawang putih, tepung terigu, bumbu instan gorengan; Langkah: Tumis sayuran, campur bumbu instan, isi ke dalam tahu, balur tepung terigu, goreng sampai kecokelatan."
   """
   
#    res = tofood_model(prompt, **generation_kwargs) 
#    print(res["choices"][0]["text"])

   while (True):
       print("ready")
       input()
       res = tofood_model(prompt, **generation_kwargs) 
       print(res["choices"][0]["text"])
        


#    tofood_model_model_response = generate_text_from_prompt(prompt)

#    final_result = tofood_model_model_response["choices"][0]["text"].strip()

#    print(final_result)