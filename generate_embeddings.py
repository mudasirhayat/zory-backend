import fitz  # PyMuPDF
import pickle
from sentence_transformers import SentenceTransformer

def split_into_chunks(text, max_chars=1000):
    lines = text.split("\n")
    chunks = []
    current = ""
    for line in lines:
if len(current) + len(line) < max_chars:
    current += line + "\n"
    chunks.append(current.strip())
            current = line + "\n"
    if current:
        chunks.append(current.strip())
    return chunks

def process_and_embed_pdf(path, source_label, model):
try:
    doc = fitz.open(path)
    full_text = "\n".join(page.get_text() for page in doc)
except Exception as e:
    print(f"An error occurred: {str(e)}")
    full_text = ""
    chunks = split_into_chunks(full_text, 1000)

    embedded_chunks = []
    for chunk in chunks:
        embedding = model.encode(chunk)
        embedded_chunks.append({
            "text": chunk,
            "embedding": embedding,
            "source": source_label,
        })
    return embedded_chunks

def main():
    model = SentenceTransformer('all-MiniLM-L6-v2')

    all_chunks = []
    all_chunks += process_and_embed_pdf("zory_faqs.pdf", "faq", model)
    all_chunks += process_and_embed_pdf("Merchant_Portal_User_Guide.pdf", "portal", model)

    with open("embeddings.pkl", "wb") as f:
        pickle.dump(all_chunks, f)

if __name__ == "__main__":
    main()
