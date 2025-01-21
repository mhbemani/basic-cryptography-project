# coco-128
coco-128 (EBC-OFB-CTR-CBC) encryption implementation in java
# not very clean duo to the limitation of time
# the purpose of the code is not to deliver packets, it's about key-generation, public-key-certificates and symmetric and asymmetric encryption 
# it has to create a RSA public key, get it's certificate from certificate-authoritie, send it to the server, server checks the validity (sends it to the CA) , then creates a symmetric key for COCO-128 (CBC MODE) ,encryp it using the user's RSA public-key and sends it back to the user. then user decrypt it and encryp the message using coco-128 symmetric key and sends it back to the server to decrypt it
# to run the program:
1. run server.java
2. run online_client.java
3. run online_CA.java
4. run online_client.java (again)
# the details will be shown in each files terminal
