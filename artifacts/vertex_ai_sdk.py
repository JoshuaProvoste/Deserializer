    def load(self, artifacts_uri str) - None
        Loads the model artifact.

        Args
            artifacts_uri (str)
                Required. The value of the environment variable AIP_STORAGE_URI.

        Raises
            ValueError If there's no required model files provided in the artifacts
                uri.
        
        prediction_utils.download_model_artifacts(artifacts_uri)
        if os.path.exists(prediction.MODEL_FILENAME_BST)
            booster = xgb.Booster(model_file=prediction.MODEL_FILENAME_BST)
        elif os.path.exists(prediction.MODEL_FILENAME_JOBLIB)
            try
                booster = joblib.load(prediction.MODEL_FILENAME_JOBLIB)
            except KeyError
                logging.info(
                    Loading model using joblib failed. 
                    Loading model using xgboost.Booster instead.
                )
                booster = xgb.Booster()
                booster.load_model(prediction.MODEL_FILENAME_JOBLIB)
        elif os.path.exists(prediction.MODEL_FILENAME_PKL)
            booster = pickle.load(open(prediction.MODEL_FILENAME_PKL, rb))