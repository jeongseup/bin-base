이렇게 에러가 발생하는데.

```
radius-builder-stack-radius-builder-6d6fd59b76-jpllw radius-builder 2026-03-18T01:23:06.899245Z ERROR builder initialization: init4_bin_base::perms::oauth: Failed to refresh oauth token err=Request failed source_chain=client error
radius-builder-stack-radius-builder-6d6fd59b76-jpllw radius-builder
radius-builder-stack-radius-builder-6d6fd59b76-jpllw radius-builder  Caused by:
radius-builder-stack-radius-builder-6d6fd59b76-jpllw radius-builder error sending request for url (https://auth.havarti.signet.sh/realms/master/protocol/openid-connect/token)
radius-builder-stack-radius-builder-6d6fd59b76-jpllw radius-builder
radius-builder-stack-radius-builder-6d6fd59b76-jpllw radius-builder  Caused by:
radius-builder-stack-radius-builder-6d6fd59b76-jpllw radius-builder client error (SendRequest)
radius-builder-stack-radius-builder-6d6fd59b76-jpllw radius-builder
radius-builder-stack-radius-builder-6d6fd59b76-jpllw radius-builder  Caused by:
radius-builder-stack-radius-builder-6d6fd59b76-jpllw radius-builder connection closed before message completed token_url="https://auth.havarti.signet.sh/realms/master/protocol/openid-connect/token" client_id="radius-builder" audience="https://transactions.parmigiana.signet.sh"
```

아래처럼 curl 로 콜하면 동작을 잘 하거든?

```
CLIENT_ID=radius-builder
CLIENT_SECRET=secret..something

curl --request POST \
 --data grant_type=client_credentials \
 --data client_id=${CLIENT_ID} \
  --data client_secret=${CLIENT_SECRET} \
 --data audience="https://transactions.parmigiana.signet.sh" \
 https://auth.havarti.signet.sh/realms/master/protocol/openid-connect/token
```

{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJGQmhSdUxLWTRwUzRUVVgzc2kxOTQ4ak96ZUhPbHJ0aW04OFJXaWIxNF84In0.eyJleHAiOjE3NzM3OTc1MjQsImlhdCI6MTc3Mzc5NzIyNCwianRpIjoiM2QzZGQwMjItY2M1OC00NDIwLWE0YzItMTBmMWU2ZmY1ZTFjIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmhhdmFydGkuc2lnbmV0LnNoL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOlsic2lnbmV0LWJ1aWxkZXIiLCJhY2NvdW50Il0sInN1YiI6IjZkNjI0NWVhLTNhOTYtNDFmMy04ZDg1LWQ3NmU4ZGI5NDBiNyIsInR5cCI6IkJlYXJlciIsImF6cCI6InJhZGl1cy1idWlsZGVyIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIvKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1tYXN0ZXIiLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsicmFkaXVzLWJ1aWxkZXIiOnsicm9sZXMiOlsidW1hX3Byb3RlY3Rpb24iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoicHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiY2xpZW50SG9zdCI6IjEyMS4xMzQuNTguMTYyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoic2VydmljZS1hY2NvdW50LXJhZGl1cy1idWlsZGVyIiwiY2xpZW50QWRkcmVzcyI6IjEyMS4xMzQuNTguMTYyIiwiY2xpZW50X2lkIjoicmFkaXVzLWJ1aWxkZXIifQ.Hu5HRwO2j1peWWfAXqC7dMTIDu6s8Dymz55LakDntbJXTGrIP_2KOuU36vpmeVmlsKas8NpCvqp-E81enuEOyssLKtAGHkmwsyBtuXg3lb_n5uRyTN8gI2I89jcSUyUwuPQIkIQOvFhGMUFA5HLiVyaH2_xkFKvvflI-Bjmsr2yKGj5P8ezGH0OAOi_dYEzNu4OFc0h4F7j6kE6UICA_rp8vzZfflD9U0ePTg86GfHA_s6ioAwtLZCsQGOkF2s612lcgVhUz6VjAppb7ypE4IuUTPjpsfvcAoLx85Z5iO5pmfDAdhPL11yxeG44nisTaXbnlbQdiOpwTVClDEhYNzw","expires_in":300,"refresh_expires_in":0,"token_type":"Bearer","not-before-policy":0,"scope":"profile email"}%

```
OAUTH_CLIENT_SECRET=.. cargo test --features perms -- perms::oauth::tests::authenticate_succeeds_with_real_credentials --ignored
```

이 테스트는 통과했는데 뭐지?
