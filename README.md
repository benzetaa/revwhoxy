<h1 align="center">RevWhoxy<br></h1>

`revwhoxy` is a tool designed to identify and retrieve other domains associated with a corporate entity, utilizing the data obtained from the WHOIS query of a primary domain as a starting point.


# Features

<h1 align="center">
  <img src="img/poc.gif" alt="Alt text" width="800px">
  <br>
</h1>



# Installation Instructions

```sh
pip install -r requirements.txt
mv .env.example .env 
```

#### API KEY

Edit the API keys in the `.env` file for better performance. Get your API at [Whoaxy](https://www.whoxy.com/account/api.php)


```sh
API_KEY_WHOXY=""
```
<br>

# Usage

```sh
python3 revwhoxy.py -d sansung.com.br
```

This will display help for the tool. Here are all the switches it supports.


```console
Usage:
  python3 revwhoxy.py [flags]

Flags:
INPUT:
  -d, --domain string   Domain for WHOIS query
```

<br>
