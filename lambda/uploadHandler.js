exports.handler = async (event) => {
    const file = event.body.file; 
    const filename = `bird_${Date.now()}.jpg`;
  
    const tags = {
      crow: Math.floor(Math.random() * 5 + 1),
      sparrow: Math.floor(Math.random() * 5 + 1)
    };
  
    const result = {
      message: "Upload successful",
      file_id: filename,
      tags: tags
    };
  
    return {
      statusCode: 200,
      body: JSON.stringify(result)
    };
  };