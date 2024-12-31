from llama_cpp import Llama


# GLOBAL VARIABLES
my_model_path = "./model/unsloth.Q4_K_M.gguf"
CONTEXT_SIZE = 10000


# LOAD THE MODEL
tofood_model = Llama(model_path=my_model_path, n_ctx=CONTEXT_SIZE)

if __name__ == "__main__":

   generation_kwargs = {
        "max_tokens":20000,
        "stop":["</s>"],
        "echo":False, # Echo the prompt in the output
        "top_k":1 # This is essentially greedy decoding, since the model will always return the highest-probability token. Set this value > 1 for sampling decoding
    }
    
   prompt ="""
   instruction:Resep ini cukup sederhana. Layak nggak untuk restoran kita? 'Yes' atau 'No' dan beri masukan.
   Resep: Sayur Lodeh; Bahan Utama: Labu Siam; Bahan: Labu siam, santan, tahu, tempe, cabai, bawang merah, bawang putih; Langkah: Masak labu dan tahu dengan santan dan bumbu hingga matang.
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