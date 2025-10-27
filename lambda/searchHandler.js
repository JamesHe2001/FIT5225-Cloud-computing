// searchHandler.js

exports.handler = async (event) => {
    const body = JSON.parse(event.body);
    const results = [];
  
    const allFiles = [ /* same structure as in mockDatabase.js */ ];
      
    for (const file of allFiles) {
      let match = true;
      for (const tag in body) {
        if (!file.tags[tag] || file.tags[tag] < body[tag]) {
          match = false;
          break;
        }
      }
      if (match) {
        results.push(file.url);
      }
    }
  
    return {
      statusCode: 200,
      body: JSON.stringify({ links: results })
    };
  };