import streamlit as st
import os
import hashlib
from cryptography.fernet import Fernet
import base64

# --- CẤU HÌNH THƯ MỤC LƯU TRỮ ---
BASE_DIR = "secure_storage"
if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)

# HÀM TẠO KEY MÃ HÓA TỪ MẬT KHẨU
def get_cipher(password: str):
    # Tạo key 32 bytes từ mật khẩu nhập vào bằng SHA256
    key = hashlib.sha256(password.encode()).digest()
    key_b64 = base64.urlsafe_b64encode(key)
    return Fernet(key_b64)

st.set_page_config(page_title="Tủ Khóa File Bảo Mật", icon="🔐", layout="centered")

st.title("🔐 Tủ Khóa & Lưu Trữ File Bảo Mật")

# --- QUẢN LÝ TẠO THƯ MỤC ---
st.sidebar.header("📁 Quản lý Thư mục")

new_folder_name = st.sidebar.text_input("Tên thư mục mới:")
new_folder_pass = st.sidebar.text_input("Mật khẩu thư mục:", type="password")

if st.sidebar.button("Tạo thư mục mới"):
    if new_folder_name and new_folder_pass:
        folder_path = os.path.join(BASE_DIR, new_folder_name)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            # Lưu hash mật khẩu để xác thực sau này
            pass_hash = hashlib.sha256(new_folder_pass.encode()).hexdigest()
            with open(os.path.join(folder_path, ".pass"), "w") as f:
                f.write(pass_hash)
            st.sidebar.success(f"Đã tạo thư mục '{new_folder_name}'!")
        else:
            st.sidebar.error("Thư mục đã tồn tại!")
    else:
        st.sidebar.warning("Vui lòng nhập đầy đủ thông tin.")

# --- DANH SÁCH THƯ MỤC ---
folders = [d for d in os.listdir(BASE_DIR) if os.path.isdir(os.path.join(BASE_DIR, d))]

if not folders:
    st.info("Chưa có thư mục nào. Hãy tạo thư mục ở thanh bên trái!")
else:
    selected_folder = st.selectbox("Chọn thư mục truy cập:", folders)
    folder_pass_input = st.text_input(f"Mật khẩu cho thư mục '{selected_folder}':", type="password")
    
    folder_path = os.path.join(BASE_DIR, selected_folder)
    pass_file = os.path.join(folder_path, ".pass")
    
    # KHI XÁC THỰC MẬT KHẨU ĐÚNG
    if folder_pass_input:
        input_hash = hashlib.sha256(folder_pass_input.encode()).hexdigest()
        with open(pass_file, "r") as f:
            stored_hash = f.read().strip()
            
        if input_hash == stored_hash:
            st.success("🔓 Đã mở khóa thư mục!")
            cipher = get_cipher(folder_pass_input)
            
            # --- TAB UPLOAD & QUẢN LÝ FILE ---
            tab1, tab2 = st.tabs(["📤 Tải tệp lên (Tự động mã hóa)", "📄 Danh sách tệp đã lưu"])
            
            with tab1:
                uploaded_files = st.file_uploader("Chọn file để lưu trữ an toàn:", accept_multiple_files=True)
                if uploaded_files:
                    for file in uploaded_files:
                        file_data = file.read()
                        encrypted_data = cipher.encrypt(file_data)
                        
                        save_path = os.path.join(folder_path, file.name + ".enc")
                        with open(save_path, "wb") as f:
                            f.write(encrypted_data)
                    st.success("Đã mã hóa và lưu trữ tất cả tệp tin thành công!")
            
            with tab2:
                all_files = [f for f in os.listdir(folder_path) if f.endswith(".enc")]
                if not all_files:
                    st.info("Thư mục này chưa có tệp tin nào.")
                else:
                    for enc_filename in all_files:
                        original_name = enc_filename[:-4] # Bỏ đuôi .enc
                        enc_file_path = os.path.join(folder_path, enc_filename)
                        
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.write(f"📄 **{original_name}**")
                        with col2:
                            with open(enc_file_path, "rb") as f:
                                enc_data = f.read()
                            try:
                                dec_data = cipher.decrypt(enc_data)
                                st.download_button(
                                    label="Tải về",
                                    data=dec_data,
                                    file_name=original_name,
                                    key=enc_filename
                                )
                            except Exception:
                                st.error("Lỗi giải mã")
        else:
            st.error("❌ Mật khẩu không chính xác!")
