import numpy as np
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import time

app = Flask(__name__)
CORS(app)
app.config["SECRET_KEY"] = "6574839201928374"
modulo = 1114111


# OBE
def obe(matrix, row_i, row_j, r):
    return matrix[row_i] + r * matrix[row_j]


# fungsi chaos henon
def henon_map(x, y, a=1.4, b=0.3):
    # rumus henon map
    x_new = 1 - a * x**2 + y
    y_new = b * x
    return x_new, y_new


def henon_key_matrix(size, initial_x=0.1, initial_y=0.1):
    # menyediakan list untuk key_matrix
    key_matrix = [[0 for _ in range(size)] for _ in range(1)]

    # inisialisasi x dan y
    x, y = initial_x, initial_y
    # hanya mengambil baris pertama dari sifat henon map yang mengeluarkan matriks 2 dimensi
    for i in range(1):
        for j in range(size):
            # menghitung x dan y dengan fungsi chaos henon map
            x, y = henon_map(0.9 * x, 0.9 * y)

            # assign key_matrix dengan nilai x dan y
            key_matrix[i][j] = int((x + y) * size) % modulo

            # melakukan penjumlahan index iterasi apabila key_matrix[i][j] bernilai 0
            if key_matrix[i][j] == 0:
                key_matrix[i][j] = ((i + j) * size) % modulo

    return key_matrix


def encrypt_key(n, x0):
    size = int(n * (n - 1) / 2)
    row = henon_key_matrix(size + n - 1, x0, x0 / 2)
    row = row[0]

    # membuat matriks identitas sebanyak n x n
    key_matrix = np.eye(n)

    # membuat matriks segitiga atas
    idx = 0
    for i in range(n):
        for j in range(i + 1, n):
            key_matrix[i, j] = row[idx]
            idx += 1

    # mengisi penuh matriks segitiga atas
    for row_i in range(1, n):
        key_matrix[row_i] = obe(key_matrix, row_i, 0, row[idx]) % modulo
        idx += 1

    return key_matrix


def decrypt_key(n, x0):
    size = int(n * (n - 1) / 2)
    row = henon_key_matrix(size + n - 1, x0, x0 / 2)
    row = row[0]

    # matriks identitas sebanyak n x n
    key_matrix = np.eye(n)

    # membuat matriks segitiga atas
    idx = 0
    for i in range(n):
        for j in range(i + 1, n):
            key_matrix[i, j] = row[idx]
            idx += 1

    # mengisi penuh matriks segitiga atas
    for row_i in range(1, n):
        key_matrix[row_i] = obe(key_matrix, row_i, 0, row[idx]) % modulo
        idx += 1

    augmented = np.zeros((n, 2 * n))
    augmented[:, :n] = key_matrix

    augmented[:, n:] = np.eye(n)

    # melakukan operasi baris elementer untuk mendapatkan invers dari kunci matriks
    # mengenolkan segitiga bawah
    for col in range(n):
        for r in range(col + 1, n):
            augmented[r] = obe(augmented, r, col, -augmented[r, col]) % modulo

    # mengenolkan segitiga atas
    for col in range(1, n):
        for r in range(col):
            augmented[r] = obe(augmented, r, col, -augmented[r, col]) % modulo

    inv_key_matrix = augmented[:, n:]

    return key_matrix, inv_key_matrix


def utf8_encode(code):
    try:
        chr(code).encode("utf-8")
    except:
        return False
    return True


@app.route("/encrypt", methods=["POST"])
def encrypt():
    start_time = time.time()
    parameters = request.json

    plaintext = parameters["plaintext"]

    len_pt = len(plaintext)
    # menghindari len_pt ganjil
    if len_pt % 2 == 1:
        plaintext += " "
    len_pt = len(plaintext)

    # convert plaintext menjadi unicode
    pt_unicode = [ord(pt) for pt in plaintext]
    np_pt_unicode = np.array(pt_unicode)

    # menghitung factor dari len_pt
    factor_len_pt = []
    for i in range(1, len_pt):
        if len_pt % i == 0:
            factor_len_pt.append(i)
            if i > 100:
                break

    # assign key2
    passkey = parameters["passkey"]
    sum = 1
    new_passkey = ""
    for i in range(len(passkey)):
        sum = 1
        for j in passkey[::-1]:
            sum += ord(passkey[i]) * ord(j)
        new_passkey += str(sum)

    key2 = float("0." + new_passkey)

    # inisialisasi key1 dan assign key2
    key1 = 0

    np_ciphertext = None
    loop_count = 0
    is_error = True

    # apabila np_pt_unicode.size <= 200, maka balikkan list factor_len_pt
    if np_pt_unicode.size <= 200:
        factor_len_pt = factor_len_pt[::-1]

    # cek factor yang akan digunakan dan semua karakter dapat di-encode oleh utf-8
    index = 0
    for f in factor_len_pt:
        # cek apakah factor habis membagi np_pt_unicode.size
        if np_pt_unicode.size % f == 0:
            if f > 500:
                key1 = factor_len_pt[index - 1]
            # cek apabila np_pt_unicode.size > 200 dan factor > 100, maka akan digunakan factor terdekat dengan angka 100
            elif np_pt_unicode.size > 200 and f > 100:
                key1 = f
                break
            # apabila np_pt_unicode.size <= 200, akan menggunakan factor terbesar
            elif np_pt_unicode.size <= 200:
                key1 = f
                break
        index += 1

    size = key1
    x0 = key2
    print(size, x0)

    # hitung matriks kunci
    key = encrypt_key(size, x0)
    # reshape np_pt_unicode untuk dapat dikalikan dengan matriks kunci
    np_pt_unicode_reshape = np_pt_unicode.reshape(
        (size, int(np_pt_unicode.size / size))
    )

    # melakukan iterasi perkalian matriks kunci dengan np_pt_unicode_reshape
    # untuk mencegah adanya unicode yang tidak dapat di-encode
    is_error = True
    is_first_iteration = True
    np_ciphertext = (key @ np_pt_unicode_reshape) % modulo
    while is_error:
        loop_count += 1
        is_error = False

        if is_first_iteration:
            is_first_iteration = False
        else:
            np_ciphertext = (key @ np_ciphertext) % modulo

        # reshape np_plaintext menjadi numpy array 1 dimensi
        np_ciphertext_reshape = np_ciphertext.reshape(len_pt).astype(np.uint32)

        # cek apakah karakter dapat di-encode
        for ct in np_ciphertext_reshape:
            if utf8_encode(ct) == False:
                is_error = True
                break

    # convert unicode menjadi karakter
    ciphertext = "".join(
        [
            chr(ct) if utf8_encode(ct) else "[#" + str(ct) + "#]"
            for ct in np_ciphertext_reshape
        ]
    )

    ciphertext += "||" + str(loop_count)

    file_path = "./files/encrypted_text_" + str(time.time()).split(".")[0] + ".txt"

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(ciphertext)

    return jsonify(
        {
            "ciphertext": ciphertext,
            "ciphertext_file_path": file_path,
            "encryption_time": time.time() - start_time,
        }
    )


@app.route(
    "/decrypt",
    methods=["POST"],
)
def decrypt():
    start_time = time.time()
    parameters = request.json

    ciphertext = parameters["ciphertext"]
    ciphertext_split = ciphertext.split("||")
    lc = int(ciphertext_split[-1])
    ciphertext = ciphertext_split[0]

    ct_unicode = [ord(ct) for ct in ciphertext]

    len_ct = len(ct_unicode)
    # menghindari len_ct ganjil
    if len_ct % 2 == 1:
        ct_unicode.append(int(32))
    len_ct = len(ct_unicode)

    # convert ct_unicode menjadi numpy array
    np_ct_unicode = np.array(ct_unicode)

    # menghitung factor dari len_ct
    factor_len_ct = []
    for i in range(1, len_ct):
        if len_ct % i == 0:
            factor_len_ct.append(i)
            if i > 100:
                break

    key1 = 0

    # apabila np_ct_unicode.size <= 200, maka balikkan list factor_len_ct
    if np_ct_unicode.size <= 200:
        factor_len_ct = factor_len_ct[::-1]

    # cek apakah factor dapat membagi habis len_ct
    index = 0
    for f in factor_len_ct:
        # cek apakah factor habis membagi np_ct_unicode.size
        if np_ct_unicode.size % f == 0:
            if f > 500:
                key1 = factor_len_ct[index - 1]
                break
            # cek apabila np_ct_unicode.size > 200 dan factor > 100, maka akan digunakan factor terdekat dengan angka 100
            elif np_ct_unicode.size > 200 and f > 100:
                key1 = f
                break
            # apabila np_ct_unicode.size <= 200, akan menggunakan factor terbesar
            elif np_ct_unicode.size <= 200:
                key1 = f
                break
        index += 1

    # assign key2
    passkey = parameters["passkey"]
    sum = 1
    new_passkey = ""
    for i in range(len(passkey)):
        sum = 1
        for j in passkey[::-1]:
            sum += ord(passkey[i]) * ord(j)
        new_passkey += str(sum)

    key2 = float("0." + new_passkey)

    size = key1
    x0 = key2
    print(size, x0)

    # hitung invers matriks kunci
    key, inv_key = decrypt_key(size, x0)
    # reshape np_pt_unicode untuk dapat dikalikan dengan matriks kunci
    np_ct_unicode_reshape = np_ct_unicode.reshape(
        (size, int(np_ct_unicode.size / size))
    )

    # melakukan iterasi perkalian matriks invers dengan np_ct_unicode_reshape
    # untuk mencegah adanya unicode yang tidak dapat di-encode
    np_plaintext = (inv_key @ np_ct_unicode_reshape) % modulo
    for i in range(lc):
        if i != 0:
            np_plaintext = (inv_key @ np_plaintext) % modulo

    # reshape np_plaintext menjadi numpy array 1 dimensi
    np_plaintext = np_plaintext.reshape(len_ct).astype(np.uint32)

    # convert unicode menjadi karakter
    plaintext = "".join([chr(pt) if utf8_encode(pt) else "" for pt in np_plaintext])

    return jsonify(
        {
            "plaintext": plaintext,
            "decryption_time": time.time() - start_time,
        }
    )


@app.route("/encrypt-file", methods=["POST"])
def encrypt_file():
    global modulo
    modulo = 256
    print("encrypting...")
    start_time = time.time()
    parameters = request.form
    file = request.files["file"]
    file_name = file.filename
    file_ext = "." + file_name.split(".")[-1]

    ord_data = np.fromfile(file, dtype="uint8")

    len_data = ord_data.size
    if len_data % 2 != 0:
        ord_data = np.append(ord_data, 32)  # 32 is space in ASCII
        len_data = ord_data.size

    factor_len_data = []
    for i in range(1, len_data):
        if len_data % i == 0:
            factor_len_data.append(i)
            if i > 100:
                break

    # assign key2
    passkey = parameters["passkey"]
    sum = 1
    new_passkey = ""
    for i in range(len(passkey)):
        sum = 1
        for j in passkey[::-1]:
            sum += ord(passkey[i]) * ord(j)
        new_passkey += str(sum)

    key1 = 0
    key2 = float("0." + new_passkey)

    # apabila ord_data.size <= 200, maka balikkan list factor_len_data
    if ord_data.size <= 200:
        factor_len_data = factor_len_data[::-1]

    # cek factor yang akan digunakan dan semua karakter dapat di-encode oleh utf-8
    index = 0
    for f in factor_len_data:
        # cek apakah factor habis membagi ord_data.size
        if ord_data.size % f == 0:
            if f > 500:
                key1 = factor_len_data[index - 1]
                break
            # cek apabila ord_data.size > 200 dan factor > 100, maka akan digunakan factor terdekat dengan angka 100
            elif ord_data.size > 200 and f > 100:
                key1 = f
                break
            # apabila ord_data.size <= 200, akan menggunakan factor terbesar
            elif ord_data.size <= 200:
                key1 = f
                break
        index += 1

    size = key1
    x0 = key2

    # hitung matriks kunci
    key = encrypt_key(size, x0)
    # reshape ord_data untuk dapat dikalikan dengan matriks kunci
    ord_data_reshape = ord_data.reshape((size, int(ord_data.size / size)))

    encrypted_ord_data = (key @ ord_data_reshape) % modulo
    encrypted_ord_data_reshape = encrypted_ord_data.reshape(len_data).astype(np.uint8)

    file_path = "./files/" + os.path.splitext(file_name)[0] + "_enc" + file_ext

    encrypted_ord_data_reshape.tofile(open(file_path, mode="wb"))

    modulo = 1114111

    return jsonify(
        {
            "file_path": file_path,
            "encryption_time": time.time() - start_time,
        }
    )


@app.route("/decrypt-file", methods=["POST"])
def decrypt_file():
    global modulo
    modulo = 256
    print("decrypting...")
    start_time = time.time()
    parameters = request.form
    file = request.files["file"]
    file_name = file.filename
    file_ext = "." + file_name.split(".")[-1]

    encrypted_ord_data = np.fromfile(file, dtype="uint8")

    len_data = encrypted_ord_data.size

    factor_len_data = []
    for i in range(1, len_data):
        if len_data % i == 0:
            factor_len_data.append(i)
            if i > 100:
                break

    # assign key2
    passkey = parameters["passkey"]
    sum = 1
    new_passkey = ""
    for i in range(len(passkey)):
        sum = 1
        for j in passkey[::-1]:
            sum += ord(passkey[i]) * ord(j)
        new_passkey += str(sum)

    key1 = 0
    key2 = float("0." + new_passkey)

    if encrypted_ord_data.size <= 200:
        factor_len_data = factor_len_data[::-1]

    # cek factor yang akan digunakan dan semua karakter dapat di-encode oleh utf-8
    index = 0
    for f in factor_len_data:
        # cek apakah factor habis membagi encrypted_ord_data.size
        if encrypted_ord_data.size % f == 0:
            if f > 500:
                key1 = factor_len_data[index - 1]
                break
            # cek apabila encrypted_ord_data.size > 200 dan factor > 100, maka akan digunakan factor terdekat dengan angka 100
            elif encrypted_ord_data.size > 200 and f > 100:
                key1 = f
                break
            # apabila encrypted_ord_data.size <= 200, akan menggunakan factor terbesar
            elif encrypted_ord_data.size <= 200:
                key1 = f
                break
        index += 1

    size = key1
    x0 = key2
    print(size, x0)

    # hitung invers matriks kunci
    key, inv_key = decrypt_key(size, x0)
    # reshape np_pt_unicode untuk dapat dikalikan dengan matriks kunci
    encrypted_ord_data_reshape = encrypted_ord_data.reshape(
        (size, int(encrypted_ord_data.size / size))
    )

    # melakukan iterasi perkalian matriks invers dengan encrypted_ord_data_reshape
    # untuk mencegah adanya unicode yang tidak dapat di-encode
    decrypted_ord_data = (inv_key @ encrypted_ord_data_reshape) % modulo

    # reshape decrypted_ord_data menjadi numpy array 1 dimensi
    decrypted_ord_data_reshape = decrypted_ord_data.reshape(len_data).astype(np.uint8)

    if decrypted_ord_data_reshape[-1] == 32:
        decrypted_ord_data_reshape = decrypted_ord_data_reshape[:-1]

    file_name = os.path.splitext(file_name)[0] + "_dec" + file_ext
    file_path = "./files/" + file_name

    decrypted_ord_data_reshape.tofile(open(file_path, mode="wb"))

    modulo = 1114111

    response = send_file(file_path, as_attachment=True)
    response.headers["x-file-name"] = file_name
    response.headers["x-decryption-time"] = time.time() - start_time
    response.headers["Access-Control-Expose-Headers"] = "x-file-name, x-decryption-time"

    return response


@app.route("/send-email-with-attachment", methods=["POST"])
def send_email_with_attachment():
    parameters = request.json

    # create message object instance
    msg = MIMEMultipart()

    # setup the parameters of the message
    sender_email = "kvnt20@gmail.com"
    password = "zosetvpyqbahecnh"

    msg["From"] = sender_email
    msg["To"] = parameters["recipient_email"]
    msg["Subject"] = "Your encrypted file"

    # add in the message body
    message = """
    Instructions:
    - Download your encrypted file.
    - Go to https://cryptography-app.vercel.app/decrypt
    - Choose mode: Upload File.
    - Upload your encrypted file.
    - Get the passkey sent to your phone number
    - Click decrypt.
    """

    if parameters["from"] == "text":
        message = """
        Instructions:
        - Download encrypted_text.txt file and open it.
        - Go to https://cryptography-app.vercel.app/decrypt
        - Choose mode: Write Text.
        - Copy your encrypted text from the file and paste it.
        - Get the passkey sent to your phone number
        - Click decrypt.

        NB: encrypted_text.txt must be downloaded, manually opened, manually copied, and manually pasted after choosing mode: Write Text.
        """

    msg.attach(MIMEText(message))

    # open the file in binary
    with open(parameters["file_path"], "rb") as attachment:
        # instance of MIMEApplication
        mime_attachment = MIMEApplication(attachment.read(), _subtype="txt")

        # add in the payload
        mime_attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=parameters["file_path"].split("/")[2],
        )
        msg.attach(mime_attachment)

    # create server
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()

    # Login
    server.login(sender_email, password)

    # send the message via the server.
    status = "success"
    try:
        server.sendmail(msg["From"], msg["To"], msg.as_string())
    except:
        status = "failed"

    # Terminate the SMTP session and close the connection
    server.quit()

    # if os.path.isfile(file_path):
    #     os.remove(file_path)

    return status


@app.route("/")
def welcome():
    return "Brewing spells..."


if __name__ == "__main__":
    app.run(debug=True)
