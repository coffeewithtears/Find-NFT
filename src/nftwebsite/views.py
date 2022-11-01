from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
import psycopg2
import requests
import json

conn = psycopg2.connect(host='127.0.0.1',
                            database='testdb',
                            user="postgres",
                            password="postgres",
                            port = "5432")
cur = conn.cursor()
views = Blueprint('views', '__name__')


@views.route('/')
@login_required
def home():
        return render_template('home.html', user=current_user)


@views.route('/nft', methods=[ 'GET', 'POST'])
@login_required
def nft():
        nft_address = request.args.get('nftaddr')
        if nft_address:   
            cur.execute("SELECT * from nft_information WHERE NFT_ADDR=%s", (nft_address,))
            conn.commit()
            if cur.fetchall(): 
                url =f"https://solana-gateway.moralis.io/nft/mainnet/{nft_address}/metadata"
                headers = {
                            "accept": "application/json",
                            "X-API-Key": "FzA6L5hendGEXQzNFOFcOAQfAqWbVNaMs8mLQNWVk1diN6nNN0DpeQWJB2HEbdsY"
                        }
                response = requests.get(url, headers=headers)
                query_sql1 = """ UPDATE nft_information SET info = (%s)  WHERE nft_addr = (%s); """
                somth = response.json
                rep = json.dumps(somth())        
                cur.execute(query_sql1, (rep,nft_address,))
                conn.commit()
                cur.execute (" select info -> 'name' from nft_information WHERE nft_addr = (%s)", (nft_address,))
                name_of_nft = cur.fetchone()
                print(name_of_nft)
                cur.execute (" select info -> 'metaplex' -> 'metadataUri' from nft_information WHERE nft_addr = (%s)", (nft_address,))
                nft_img_url = cur.fetchone()
                print()
                cur.execute (" select info -> 'mint'  from nft_information WHERE nft_addr = (%s)", (nft_address,))
                nft_mint = cur.fetchone()
                return render_template('index.html', nm=name_of_nft[0], imgurl = nft_img_url[0], mint = nft_mint[0], user=current_user)
            else:
                cur.execute("INSERT INTO nft_information (NFT_ADDR) VALUES (%s)", (nft_address,))
                conn.commit()
                return render_template('create.html', user=current_user)
        return render_template('create.html', user=current_user)



