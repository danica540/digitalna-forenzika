# digitalna-forenzika

## Usage

**Starting**
```bash
docker-compose up -d
pipenv shell && pipenv sync
```

**Analyzing packet**
```bash
python digi --file ./samples/sample.pcapng --ip 192.168.0.108
```
