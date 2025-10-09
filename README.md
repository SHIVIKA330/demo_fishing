## 🚀 Cloud Deployment (Render)

The backend is deployed on Render for automatic 24/7 operation. No manual setup required!

### For Users:
1. Simply install the extension from the ZIP file
2. The extension will automatically connect to the cloud backend
3. No Python or Flask setup needed!

### For Developers:
To deploy your own instance:

1. Fork this repository
2. Create account on [Render.com](https://render.com)
3. Connect your GitHub repository
4. Create a new Web Service
5. Set build command: `pip install -r requirements.txt`
6. Set start command: `gunicorn app:app`
7. Deploy!

Update the `BACKEND_URL` in `background.js` and `popup.js` with your Render URL.
