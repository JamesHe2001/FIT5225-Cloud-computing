# 5225_assignment
👥 Team Members
    Chaoyang Zheng(34665099)
    Tianyi Song(34621830)
    Xi He(31159214)
    Yuchen Chi (33782695)

# 🐦BirdTag – An AWS-Powered Serverless Media Tagging System
    This is a serverless media storage and bird species tagging system built for the **FIT5225 Assignment 3** at Monash University. The system is designed to help Monash Birdy Buddies (MBB) upload, store, tag, and query multimedia files (images, audio, video) related to bird species across campuses.

---

##  Project Features
### Core Functionalities:
    - Upload images/audio/video files via web interface
    - Automatic thumbnail generation for images
    - Bird species detection using pretrained ML models
    - Store tags and metadata in DynamoDB
    - Search files based on species and counts
    - Manage tags (add/remove in bulk)
    - Delete files and related data from the system
    - Email notifications (optional via AWS SNS)
    - Cognito-based authentication and access control

---

##  Technologies Used
    | Component | Service |
    |----------|---------|
    | Authentication | AWS Cognito |
    | Media Storage | AWS S3 |
    | Serverless Compute | AWS Lambda |
    | API Management | AWS API Gateway |
    | Database | AWS DynamoDB |
    | Notification (Optional) | AWS SNS |
    | UI | HTML + JavaScript (Vanilla) |

---

##  Deployment Structure
    ```text
    S3 Buckets
    ├── /media/ (raw uploads)
    └── /thumbs/ (image thumbnails)

    Lambda Functions
    ├── imageThumbnailGenerator
    ├── birdTagger (model inference + DB write)
    ├── queryHandler
    └── tagManager / deleteHandler

    Cognito
    ├── User Pool (auth)
    └── App Client

    API Gateway
    ├── /upload
    ├── /search
    ├── /add-tags
    └── /delete
    Repository Structure
        birdtag
        ┣ 📂lambdas
        ┃ ┣ lambda_thumbnail.py
        ┃ ┣ lambda_tagger.py
        ┃ ┣ lambda_query.py
        ┣ 📂html
        ┃ ┣ login.html
        ┃ ┣ upload.html
        ┃ ┣ search.html
        ┃ ┗ js/
        ┃   ┣ auth.js
        ┃   ┣ upload.js
        ┃   ┗ search.js
        ┣ README.md
        ┣ architecture.png
        ┗ requirements.txt

📌 Notes
	•	This project uses only serverless AWS services within Academy limitations.
	•	All code is contained in a private GitHub repository and is not publicly available to ensure academic integrity.
	•	The pretrained models used for tagging are sourced from BirdNET and other open-source frameworks.
