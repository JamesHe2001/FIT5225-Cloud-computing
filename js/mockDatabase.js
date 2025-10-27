const mockFiles = [
    {
      id: "file1.jpg",
      url: "https://example.com/file1.jpg",
      type: "image",
      tags: { crow: 3, bird: 2 }
    },
    {
      id: "file2.mp4",
      url: "https://example.com/file2.mp4",
      type: "video",
      tags: { eagle: 5, sky: 1 }
    }
  ];
  
  function getFileById(fileId) {
    return mockFiles.find(file => file.id === fileId);
  }
  
  function searchFiles(tag, minCount) {
    return mockFiles.filter(file => file.tags[tag] >= minCount);
  }
  
  function addFile(file) {
    mockFiles.push(file);
  }
  
  module.exports = { getFileById, searchFiles, addFile };