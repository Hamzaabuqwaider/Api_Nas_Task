# Api_Nas_Task

POST  /api/auth/register
* Create user in the table user database
- Request arguments: {first_name:string,last_name:string,username:string,email:email,data_of_birth:date-format,password:string,gender:optional,phone_number:optional}
- 401 - if the all or one/two param was not provided.
- 500 - if param was any error
- 200 - the user created

POST /api/auth/login
- Request arguments: {username:string,password:string}
- 401 - if the all or one/two param was not provided.
- 402 - if the username or password not true
- 500 - if param was any error
- 200 - the user logged in

GET /api/auth/user_info
- Request arguments:token from logged in and input in bearer Authorization
- 401 - if the user not found
- 200 - get user information auth and authorization
- 500 - of any error show in the catch error
