# SSL Generator

Use a simple CLI application to issue an SSL certificate and get it signed by LetsEncrypt Authority </br>
Domains should be divided by comma without spaces and the top-level domain
of every domain stated in command line should be same </br>
The task description by the teacher: [SSL Generator](https://github.com/nosovk/students-micro-tasks/blob/main/tasks/task-ssl-generator.md)

1. npm install
2. npm start mailbox@example.com example.com,sub1.example.com,sub2.example.com
3. Follow instructions in CLI
4. Receive signed certificate saved in local directory openssl/example.com.cert
