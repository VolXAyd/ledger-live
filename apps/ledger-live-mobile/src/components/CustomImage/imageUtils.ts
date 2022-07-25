import { Alert, Image } from "react-native";
import RNFetchBlob, { FetchBlobResponse, StatefulPromise } from "rn-fetch-blob";
import { launchImageLibrary } from "react-native-image-picker";
import * as ImagePicker from "expo-image-picker";
import { ImageDimensions, ImageFileUri, ImageUrl } from "./types";
import {
  ImageDownloadError,
  ImageLoadFromGalleryError,
  ImageMetadataLoadingError,
  ImageTooLargeError,
} from "./errors";

export async function importImageFromPhoneGalleryExpo(): Promise<
  (ImageFileUri & Partial<ImageDimensions>) | null
> {
  try {
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ImagePicker.MediaTypeOptions.Images,
      allowsEditing: false,
      quality: 1,
      base64: false,
    });
    Alert.alert("result", JSON.stringify(result, null, 2));
    if (result.cancelled) {
      Alert.alert("cancelled");
      return null;
    }
    const { uri, width, height } = result;
    if (uri) {
      return {
        width,
        height,
        imageFileUri: uri,
      };
    }
    throw new Error("uri is falsy");
  } catch (e) {
    console.error(e);
    Alert.alert("error", (e as Error).toString());
    throw new ImageLoadFromGalleryError();
  }
}

export async function importImageFromPhoneGallery(): Promise<
  (ImageFileUri & Partial<ImageDimensions>) | null
> {
  try {
    const result = await launchImageLibrary({
      mediaType: "photo",
      quality: 1,
      includeBase64: false,
    });
    Alert.alert("result", JSON.stringify(result, null, 2));
    const { assets, didCancel, errorCode, errorMessage } = result;
    if (didCancel) {
      Alert.alert("didCancel");
      return null;
    }
    if (errorCode) throw new Error(errorMessage);
    const asset = assets && assets[0];
    if (!asset) throw new Error("asset is falsy");
    const { uri, width, height } = asset;
    if (uri) {
      return {
        width,
        height,
        imageFileUri: uri,
      };
    }
    throw new Error("uri is falsy");
  } catch (e) {
    console.error(e);
    Alert.alert("error", (e as Error).toString());
    throw new ImageLoadFromGalleryError();
  }
}

export async function fetchImageBase64(imageUrl: string) {
  return fetch(imageUrl)
    .then(response => response.blob())
    .then(
      data =>
        new Promise<string | undefined>((resolve, reject) => {
          const reader = new FileReader(); // eslint-disable-line no-undef
          reader.onloadend = () => resolve(reader.result?.toString());
          reader.onerror = reject;
          reader.readAsDataURL(data);
        }),
    );
}

export function downloadImageToFileWithCancellable({
  imageUrl,
}: ImageUrl): [Promise<ImageFileUri>, StatefulPromise<FetchBlobResponse>] {
  const downloadTask = RNFetchBlob.config({ fileCache: true }).fetch(
    "GET",
    imageUrl,
  );
  return [
    downloadTask
      .then(res => ({ imageFileUri: "file://" + res.path() }))
      .catch(() => {
        throw new ImageDownloadError();
      }),
    downloadTask,
  ];
}

export async function downloadImageToFile({
  imageUrl,
}: ImageUrl): Promise<ImageFileUri> {
  return downloadImageToFileWithCancellable({ imageUrl })[0];
}

export async function loadImageToFileWithDimensions(
  source: Partial<ImageUrl> & Partial<ImageFileUri> & Partial<ImageDimensions>,
): Promise<ImageFileUri & Partial<ImageDimensions>> {
  if (source?.imageFileUri) {
    return {
      imageFileUri: source?.imageFileUri,
      height: source?.height,
      width: source?.width,
    };
  }
  if (source?.imageUrl) {
    const { imageUrl } = source;
    const [downloadPromise, downloadTask] = downloadImageToFileWithCancellable({
      imageUrl,
    });
    try {
      const [dims, { imageFileUri }] = await Promise.all([
        loadImageSizeAsync(imageUrl),
        downloadPromise,
      ]);
      return {
        width: dims.width,
        height: dims.height,
        imageFileUri,
      };
    } catch (e) {
      /**
       * in case an error happens in loadImageSizeAsync we have to cancel the
       * download task
       * */
      downloadTask.cancel();
      throw e;
    }
  }
  throw new Error("No source specified"); // this shouldn't happen
}

export async function loadImageSizeAsync(
  url: string,
): Promise<ImageDimensions> {
  return new Promise((resolve, reject) => {
    Image.getSize(
      url,
      (width, height) => {
        resolve({ width, height });
      },
      error => {
        console.error(error);
        if (error?.message?.startsWith("Pool hard cap violation? ")) {
          reject(new ImageTooLargeError());
        } else {
          reject(new ImageMetadataLoadingError());
        }
      },
    );
  });
}

export function fitImageContain(
  imageDimensions: ImageDimensions,
  boxDimensions: ImageDimensions,
): { height: number; width: number } {
  const { height: imageHeight, width: imageWidth } = imageDimensions;
  const { height: boxHeight, width: boxWidth } = boxDimensions;
  if (imageHeight < boxHeight && imageWidth < boxWidth)
    return {
      width: imageWidth,
      height: imageHeight,
    };
  if (imageWidth / imageHeight >= boxWidth / boxHeight) {
    // width is the constraint
    return {
      width: boxWidth,
      height: (imageHeight / imageWidth) * boxWidth,
    };
  }
  // height is the constraint
  return {
    width: (imageWidth / imageHeight) * boxHeight,
    height: boxHeight,
  };
}
