# upload_sample

Install dbmate. And then:

```
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/mam_dev?sslmode=disable"
dbmate create
dbmate up

go run .

# or
go build -o mam-server
./mam-server
```
