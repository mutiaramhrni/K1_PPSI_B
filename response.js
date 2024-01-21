const response = (status,data,message,res)=>{
  res.json(status,[
    {
      payload:data,message,
      metadata:{
        prev:"",
        next:"",
        current:""
      }
    }
  ])
}

module.exports= response;