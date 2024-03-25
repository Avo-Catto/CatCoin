from socket import create_connection, SHUT_WR
from json import loads

ADDRESS = "127.0.0.1:8000"

transaction0 = b'{"dtype": 1, "data":{"broadcast":false,"date":"today","dst":"anyone else","hash":"224C5149032233E06894AC13D22CD21C64E1517BD721EA294D5076534EE72A3C","src":"avo-catto","val":0.3}}'
transaction1 = '{"dtype": 1, "data":{\"broadcast\":false,\"date\":\"2024-03-06T18:13:55.434499883+00:00\",\"dst\":\"0df8b7ff-57fd-4c19-8253-907a447915ec\",\"hash\":\"2A7DCCC532AB77015965BDE100E9CF23F406ACC16F091C89C1256C5D54BEEB5D\",\"src\":\"793456ca-cdcb-4b92-9147-1e63bea77742\",\"val\":0.8}}'.replace('\"', '"').encode()
transaction2 = '{"dtype": 1, "data":{\"broadcast\":false,\"date\":\"2024-03-06T17:41:36.301061222+00:00\",\"dst\":\"6661c67f-6c29-4798-a49c-7a583b101298\",\"hash\":\"2D2F07CB7D11CF68ECA5F8A5337C37082ED1BA39EB1CA2E46DF221338A1001E0\",\"src\":\"28b8e910-7d29-4b60-ab45-22431851bc18\",\"val\":0.4}}'.replace('\"', '"').encode()

block0 = '{"dtype": 2, "data":{\"datetime\":\"2024-03-07T16:02:28.819491703+00:00\",\"hash\":\"55413FB3744291D336F35BAF20F69F4029971C87CF28B7E477E2C8C23629FE8F\",\"index\":1,\"merkle\":\"5FF890828A475ED0BFDB18D04BD9E585302408C7F1EB8F345BBF3D93790F8B26\",\"nonce\":2,\"previous_hash\":\"F9C9BAAC9006160A6D84A09E77CBFEAC349C861513E1786EA447E00198068E20\",\"transactions\":[{\"broadcast\":false,\"date\":\"2024-03-07T16:02:28.819419467+00:00\",\"dst\":\"4b5066a6-e885-4f40-bed4-dc22af6c916b\",\"hash\":\"707C1C92B34D6FF17C643887608F55C5DEBC336FA47666E5B9E14E49AFECE417\",\"src\":\"8009044d-53c7-408e-963d-379bd07aa300\",\"val\":0.4},{\"broadcast\":false,\"date\":\"2024-03-07T16:02:28.819471930+00:00\",\"dst\":\"a843c5ca-8cfc-4efb-8597-0276b58f2b0d\",\"hash\":\"B29C57B582B3A41EF060D7B38A1B5CA8344B1444272B8B8F42D886148C1277D6\",\"src\":\"ad9b1d7e-d816-442d-99bb-7ab720cead9c\",\"val\":0.8}]}}'.replace('\"', '"').encode()

with create_connection(ADDRESS.split(":")) as con:
    con.send(transaction1)
    con.shutdown(SHUT_WR)
    
    res = con.recv(1024).decode()
    
    if loads(res)['res'] == 1: print('transmission succeed!')
    else: print('transmission failed!')

# 2024-03-08T18:30:48.803287
# 2024-03-06T17:41:36.301061222+00:00
# 2024-03-08T21:23:11.56046800+01:00

# 1988585BEC1C6B6ABC68D34FE007FC6DAA44B0B196889371F926DD25F4CBDEA3
# 0A2782E9D963628027C3FBCFB0100022E567B4C7DED95700B7DF549C2CF0F584