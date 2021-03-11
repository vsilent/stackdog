## Welcome!

Stackdog - is a server management tool written in Rust that allows users to manage their servers especially containerized applications.

#### Status 

<div markdown="span" class="alert alert-warning" role="alert"><i class="fa fa-warning-circle"></i>

:warning: We have just started our development ! Stay tuned !

</div>

### Quickstart

#### Using cargo
```
cargo install stackdog
```

#### Using docker
```
docker run -d -p 5000:5000 --restart=always -v /var/run/docker.sock:/var/run/docker.sock --name=stackdog -v stackdog_data:/data trydirect/stackdog
```


