// getFileDetail.js

exports.handler = async (event) => {
    const fileId = event.queryStringParameters.file_id;
  
    const file = {
      id: fileId,
      full_url: `https://s3.amazonaws.com/birdtag/${fileId}`,
      file_type: fileId.endsWith(".mp4") ? "video" : "image",
      tags: { crow: 2, eagle: 1 }
    };
  
    return {
      statusCode: 200,
      body: JSON.stringify(file)
    };
  };